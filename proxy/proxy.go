package proxy

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cockroachdb/crlib/fifo"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

type Handler interface {
	fmt.Stringer
	Release()
	SetRejected(retry bool)
	GetPreAllocator() *PreAllocator
	ObfuscateTraffic() *bool
}

type localContext struct {
	nlHandle *netlink.Handle
	prefix   *net.IPNet
	mark     uint32
	ipv6     bool
	obfIdx   int
}

type GetHandlerFunc func(cancel context.CancelFunc, inode uint32) Handler

type Proxy struct {
	finalizers []func(*zap.Logger)

	breaker circuitBreaker

	userLimit  *fifo.Semaphore
	totalLimit *fifo.Semaphore
	getFunc    atomic.Pointer[GetHandlerFunc]
	defaultObf atomic.Bool

	wg     sync.WaitGroup
	connWg sync.WaitGroup
	cancel context.CancelFunc
}

var pwnbotId = []byte("pwnbot")

func cleanupRules(logger *zap.Logger, conn *nftables.Conn, table *nftables.Table, chains ...*nftables.Chain) {
	for _, chain := range chains {
		rules, err := conn.GetRules(table, chain)
		if err != nil {
			logger.Error("failed to get existing rules", zap.Error(err), zap.String("table", table.Name), zap.String("chain", chain.Name))
			continue
		}
		for _, rule := range rules {
			if bytes.Equal(rule.UserData, pwnbotId) {
				if err := conn.DelRule(rule); err != nil {
					logger.Error("failed deleting rule", zap.Error(err), zap.String("table", table.Name), zap.String("chain", chain.Name))
				}
			}
		}
	}
}

func getTableAndChains(ipv6 bool) (*nftables.Table, *nftables.Chain, *nftables.Chain, *nftables.Chain) {
	table := &nftables.Table{
		Name: "nat",
	}
	if ipv6 {
		table.Family = nftables.TableFamilyIPv6
	} else {
		table.Family = nftables.TableFamilyIPv4
	}

	chainPrerouting := &nftables.Chain{
		Name:     "PREROUTING",
		Table:    table,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityNATDest,
		Type:     nftables.ChainTypeNAT,
	}

	chainOutput := &nftables.Chain{
		Name:     "OUTPUT",
		Table:    table,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityNATDest,
		Type:     nftables.ChainTypeNAT,
	}

	chainPostrouting := &nftables.Chain{
		Name:     "POSTROUTING",
		Table:    table,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityNATSource,
		Type:     nftables.ChainTypeNAT,
	}

	return table, chainPrerouting, chainOutput, chainPostrouting
}

func CleanupRules(logger *zap.Logger) {
	conn, err := nftables.New()
	if err != nil {
		logger.Error("failed to create nftables connection", zap.Error(err))
		return
	}

	table, chain1, chain2, chain3 := getTableAndChains(false)
	cleanupRules(logger, conn, table, chain1, chain2, chain3)
	table, chain1, chain2, chain3 = getTableAndChains(true)
	cleanupRules(logger, conn, table, chain1, chain2, chain3)

	if err := conn.Flush(); err != nil {
		logger.Error("failed to flush nftables rules", zap.Error(err))
	}
}

func CreateProxy(ctx context.Context, logger *zap.Logger, prefix netip.Prefix, nsPath string) (*Proxy, error) {
	if !prefix.IsValid() {
		return &Proxy{
			userLimit:  fifo.NewSemaphore(1),
			totalLimit: fifo.NewSemaphore(1),
		}, nil
	}
	prefix = prefix.Masked()

	finalizers := make([]func(*zap.Logger), 0, 5)
	defer func() {
		for i := len(finalizers) - 1; i >= 0; i-- {
			finalizers[i](logger)
		}
	}()

	nlHandle, err := func() (*netlink.Handle, error) {
		ns, err := netns.GetFromPath(nsPath)
		if err != nil {
			logger.Error("failed to get netns from path", zap.Error(err))
			return nil, err
		}
		defer func() {
			if err := ns.Close(); err != nil {
				logger.Error("failed to close netns", zap.Error(err))
			}
		}()

		nlHandle, err := netlink.NewHandleAt(ns, syscall.NETLINK_INET_DIAG)
		if err != nil {
			logger.Error("failed to create netlink handle", zap.Error(err))
			return nil, err
		}
		return nlHandle, nil
	}()
	if err != nil {
		return nil, err
	}
	finalizers = append(finalizers, func(*zap.Logger) {
		nlHandle.Close()
	})

	isIpv6 := prefix.Addr().Is6()

	obfLink, err := createObfuscatorTun(logger, isIpv6)
	if err != nil {
		logger.Error("failed to create obfuscator tun", zap.Error(err))
		return nil, err
	}

	if isIpv6 {
		if err := netlink.RouteAdd(&netlink.Route{
			LinkIndex: obfLink.Index,
			Dst:       &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
		}); err != nil {
			logger.Error("failed to add route for obfuscator tun", zap.Error(err))
			return nil, err
		}
	}

	var listenAddr, listenNetwork string
	if isIpv6 {
		listenNetwork = "tcp6"
		listenAddr = "[::]:0"
	} else {
		listenNetwork = "tcp4"
		listenAddr = "0.0.0.0:0"
	}

	listener, err := new(net.ListenConfig).Listen(ctx, listenNetwork, listenAddr)
	if err != nil {
		logger.Error("failed to create listener", zap.Error(err))
		return nil, err
	}
	finalizers = append(finalizers, func(logger *zap.Logger) {
		if err := listener.Close(); err != nil {
			logger.Error("failed to close listener", zap.Error(err))
		}
	})
	listenedAddr := listener.Addr().(*net.TCPAddr)
	logger.Info("listening on", zap.Stringer("address", listenedAddr))

	conn, err := nftables.New()
	if err != nil {
		logger.Error("failed to create nftables connection", zap.Error(err))
		return nil, err
	}

	table, chainPrerouting, chainOutput, chainPostrouting := getTableAndChains(isIpv6)
	cleanupRules(logger, conn, table, chainPrerouting, chainOutput)
	conn.AddTable(table)
	conn.AddChain(chainPrerouting)
	conn.AddChain(chainOutput)

	if isIpv6 {
		conn.AddRule(&nftables.Rule{
			Table: table,
			Chain: chainPostrouting,
			Exprs: []expr.Any{
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       8,  // IPv6 source address offset
					Len:          16, // IPv6 address length
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     rewrittenIpv6,
				},
				&expr.Masq{},
			},
			UserData: pwnbotId,
		})
	} else {
		conn.AddRule(&nftables.Rule{
			Table: table,
			Chain: chainPostrouting,
			Exprs: []expr.Any{
				&expr.Payload{
					DestRegister: 1,
					Base:         expr.PayloadBaseNetworkHeader,
					Offset:       12, // IPv4 source address offset
					Len:          4,  // IPv4 address length
				},
				&expr.Cmp{
					Op:       expr.CmpOpEq,
					Register: 1,
					Data:     rewrittenIpv4.To4(),
				},
				&expr.Masq{},
			},
			UserData: pwnbotId,
		})
	}

	ipnet := prefixToIpNet(prefix)
	mark := rand.Uint32()

	commonExprs := []expr.Any{
		&expr.Meta{
			Key:      expr.MetaKeyIIF,
			Register: 1,
		},
		&expr.Cmp{
			Op:       expr.CmpOpNeq,
			Register: 1,
			Data:     binary.LittleEndian.AppendUint32(nil, uint32(obfLink.Index)),
		},
		&expr.Meta{
			Key:      expr.MetaKeyL4PROTO,
			Register: 1,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{syscall.IPPROTO_TCP},
		},
	}

	if isIpv6 {
		commonExprs = append(commonExprs,
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       24, // IPv6 destination address offset
				Len:          16, // IPv6 address length
			},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            16,
				Mask:           ipnet.Mask,
				Xor:            make([]byte, 16), // No XOR operation
			},
		)
	} else {
		commonExprs = append(commonExprs,
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       16, // IPv4 destination address offset
				Len:          4,  // IPv4 address length
			},
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           ipnet.Mask,
				Xor:            []byte{0, 0, 0, 0}, // No XOR operation
			},
		)
	}

	commonExprs = append(commonExprs,
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     ipnet.IP,
		},
		&expr.Immediate{
			Register: 1,
			Data:     binary.BigEndian.AppendUint16(nil, uint16(listenedAddr.Port)),
		},
		&expr.Redir{
			RegisterProtoMin: 1,
		},
	)

	conn.AddRule(&nftables.Rule{
		Table:    table,
		Chain:    chainPrerouting,
		Exprs:    commonExprs,
		UserData: pwnbotId,
	})

	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: chainOutput,
		Exprs: append([]expr.Any{
			&expr.Meta{
				Key:      expr.MetaKeyMARK,
				Register: 1,
			},
			&expr.Cmp{
				Op:       expr.CmpOpNeq,
				Register: 1,
				Data:     binary.LittleEndian.AppendUint32(nil, mark),
			}},
			commonExprs...,
		),
		UserData: pwnbotId,
	})

	if err := conn.Flush(); err != nil {
		logger.Error("failed to flush nftables rules", zap.Error(err))
		return nil, err
	}

	logger.Debug("inserted nftables rule", zap.String("table", table.Name), zap.Stringer("prefix", prefix))

	finalizers = append(finalizers, func(logger *zap.Logger) {
		cleanupRules(logger, conn, table, chainPrerouting, chainOutput)
		if err := conn.Flush(); err != nil {
			logger.Error("failed to flush nftables rules", zap.Error(err))
		}
	})

	proxy := &Proxy{
		userLimit:  fifo.NewSemaphore(1),
		totalLimit: fifo.NewSemaphore(1),
	}
	var nilHandler GetHandlerFunc
	proxy.getFunc.Store(&nilHandler)

	stopObf := make(chan struct{})
	if err := proxy.runObfuscator(stopObf, logger, obfLink); err != nil {
		logger.Error("failed to run obfuscator", zap.Error(err))
		return nil, err
	}
	finalizers = append(finalizers, func(*zap.Logger) {
		close(stopObf)
	})

	proxy.finalizers, finalizers = finalizers, nil

	ctx, cancel := context.WithCancel(ctx)
	proxy.cancel = cancel

	proxy.wg.Add(1)
	go proxy.run(ctx, logger, listener, localContext{
		nlHandle: nlHandle,
		prefix:   ipnet,
		mark:     mark,
		ipv6:     isIpv6,
		obfIdx:   obfLink.Index,
	})

	return proxy, nil
}

func (p *Proxy) Stop(logger *zap.Logger) {
	defer p.wg.Wait()
	p.cancel()
	p.connWg.Wait()
	for i := len(p.finalizers) - 1; i >= 0; i-- {
		p.finalizers[i](logger)
	}
	p.finalizers = nil
}

func (p *Proxy) SetHandler(handler GetHandlerFunc) {
	p.getFunc.Store(&handler)
}

func (p *Proxy) UpdateParam(totalLimit, userLimit uint, defaultObfuscate bool) {
	p.totalLimit.UpdateCapacity(int64(totalLimit))
	p.userLimit.UpdateCapacity(int64(userLimit))
	p.defaultObf.Store(defaultObfuscate)
}

func (p *Proxy) PreAllocate(ctx context.Context, logger *zap.Logger, count int64) *PreAllocator {
	if p == nil || count == 0 {
		return &PreAllocator{
			logger: logger,
			count:  0,
		}
	}

	p.breaker.backoff(ctx, logger)

	if err := p.totalLimit.Acquire(ctx, count); err != nil {
		if !errors.Is(err, context.Canceled) {
			logger.Error("failed to acquire semaphore for pre-allocation", zap.Error(err), zap.Int64("count", count))
		}
		return nil
	}

	allocator := &PreAllocator{
		logger:    logger,
		count:     count,
		allocated: fifo.NewSemaphore(count),
		limit:     p.totalLimit,
	}
	return allocator
}

func (p *Proxy) run(ctx context.Context, logger *zap.Logger, listener net.Listener, local localContext) {
	defer p.wg.Done()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				logger.Info("listener closed, stopping proxy")
			} else {
				// can we recover
				logger.Error("failed to accept connection", zap.Error(err))
			}
			return
		}
		p.connWg.Add(1)
		go p.proxyConn(ctx, logger, conn.(*net.TCPConn), local)
	}
}

func getOriginalDst(conn *net.TCPConn, ipv6 bool) (*net.TCPAddr, error) {
	syscallConn, err := conn.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("failed to get syscall connection: %w", err)
	}

	if ipv6 {
		var addrReq syscall.RawSockaddrInet6
		outerErr := syscallConn.Control(func(fd uintptr) {
			err = getSockOpt(fd, syscall.IPPROTO_IPV6, unix.SO_ORIGINAL_DST, &addrReq)
		})
		if err == nil {
			err = outerErr
		}
		if err != nil {
			return nil, err
		}
		return &net.TCPAddr{
			IP:   addrReq.Addr[:],
			Port: int(binary.LittleEndian.Uint16(binary.BigEndian.AppendUint16(nil, addrReq.Port))),
		}, nil
	}

	var addrReq syscall.RawSockaddrInet4
	outerErr := syscallConn.Control(func(fd uintptr) {
		err = getSockOpt(fd, syscall.IPPROTO_IP, unix.SO_ORIGINAL_DST, &addrReq)
	})
	if err == nil {
		err = outerErr
	}
	if err != nil {
		return nil, err
	}
	return &net.TCPAddr{
		IP:   addrReq.Addr[:],
		Port: int(binary.LittleEndian.Uint16(binary.BigEndian.AppendUint16(nil, addrReq.Port))),
	}, nil
}

func (p *Proxy) proxyConn(ctx context.Context, logger *zap.Logger, conn net.Conn, local localContext) {
	defer p.connWg.Done()
	defer func() {
		if err := conn.Close(); err != nil {
			logger.Error("failed to close connection", zap.Error(err))
		}
	}()

	addr, err := getOriginalDst(conn.(*net.TCPConn), local.ipv6)
	if err != nil {
		logger.Error("failed to get socket options", zap.Error(err))
		return
	}

	logger = logger.With(
		zap.Stringer("from", conn.RemoteAddr()),
		zap.Stringer("target", addr),
	)
	defer func() { logger.Debug("closing connection") }()
	logger.Debug("new connection")

	if !local.prefix.Contains(addr.IP) {
		logger.Debug("connection to non-proxy address, rejecting")
		return
	}

	socketInfo, _ := local.nlHandle.SocketGet(conn.RemoteAddr(), addr) // the reverse gets the other end
	if socketInfo != nil && socketInfo.INode == 0 {
		logger.Debug("no inode found for connection, rejecting")
		return
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var handler Handler
	if socketInfo != nil {
		if get := *p.getFunc.Load(); get != nil {
			handler = get(cancel, socketInfo.INode)
			if handler != nil {
				defer handler.Release()
				logger = logger.With(zap.Stringer("task", handler))
			}
		}
	}

	past := time.Now()

	if handler == nil {
		// no handler -> this is a user connection
		if p.userLimit.Acquire(ctx, 1) != nil {
			return
		}
		defer p.userLimit.Release(1)
	}

	if handler == nil {
		// if user connection, we block
		if p.totalLimit.Acquire(ctx, 1) != nil {
			return
		}
		defer p.totalLimit.Release(1)
	} else {
		pre := handler.GetPreAllocator()
		if pre.transfer() {
			defer pre.put()
		} else {
			if !p.totalLimit.TryAcquire(1) {
				logger.Warn("semaphore limit reached, rejecting connection")
				handler.SetRejected(false)
				return
			}
			defer p.totalLimit.Release(1)
		}
	}

	logger.Debug("accepted connection")

	needObf := func() bool {
		if handler == nil {
			// user connection
			return p.defaultObf.Load()
		}
		if obf := handler.ObfuscateTraffic(); obf != nil {
			return *obf
		}
		return p.defaultObf.Load()
	}()
	if needObf {
		logger.Debug("using traffic obfuscation")
	}

	dialer := net.Dialer{
		Control: func(_, _ string, c syscall.RawConn) (err error) {
			outerErr := c.Control(func(fd uintptr) {
				err = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, int(local.mark))
				if err != nil {
					return
				}
				// set linger to 3 secs
				err = syscall.SetsockoptLinger(int(fd), syscall.SOL_SOCKET, syscall.SO_LINGER, &syscall.Linger{Onoff: 1, Linger: 3})
				if err != nil {
					return
				}

				if needObf {
					err = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, unix.SO_BINDTOIFINDEX, local.obfIdx)
					if err != nil {
						return
					}
					err = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, 0)
					if err != nil {
						return
					}
				}
			})
			if outerErr != nil {
				return outerErr
			}
			return
		},
		Timeout: time.Second * 3,
	}
	forwardConn, err := dialer.DialContext(ctx, "tcp", addr.String())
	if err != nil {
		if errors.Is(err, os.ErrDeadlineExceeded) {
			p.breaker.trip() // connection hanged (rejected)
			if handler != nil {
				handler.SetRejected(true)
			}
		}
		if !errors.Is(err, context.Canceled) {
			logger.Error("failed to dial forward connection", zap.Error(err), zap.Stringer("address", addr))
		}
		return
	}
	defer func() {
		if err := forwardConn.Close(); err != nil {
			logger.Error("failed to close forward connection", zap.Error(err))
		}
	}()

	p.breaker.reset(logger)

	finished := make(chan struct{}, 2)
	go func() { // conn -> forwardConn
		defer func() {
			finished <- struct{}{}
		}()
		defer func() {
			if err := forwardConn.(*net.TCPConn).CloseWrite(); err != nil && !errors.Is(err, syscall.ENOTCONN) {
				logger.Error("failed to close write side of forward connection", zap.Error(err))
			}
		}()

		if _, err := io.Copy(forwardConn, conn); notOkCopy(err) {
			logger.Error("failed to copy data from connection to forward connection", zap.Error(err))
		}
	}()

	go func() { // forwardConn -> conn
		defer func() {
			finished <- struct{}{}
		}()
		defer func() {
			if err := conn.(*net.TCPConn).CloseWrite(); err != nil && !errors.Is(err, syscall.ENOTCONN) {
				logger.Error("failed to close write side of connection", zap.Error(err))
			}
		}()

		if _, err := io.Copy(conn, forwardConn); notOkCopy(err) {
			logger.Error("failed to copy data from forward connection to connection", zap.Error(err))
		}
	}()

	var collected int
	for collected < 2 {
		select {
		case <-finished:
			collected++
			continue
		case <-ctx.Done():
			if err := forwardConn.SetDeadline(past); err != nil {
				logger.Error("error setting deadline on forward connection", zap.Error(err))
			}

			if err := conn.SetDeadline(past); err != nil {
				logger.Error("error setting deadline on connection", zap.Error(err))
			}
		}
		break
	}
	for collected < 2 {
		<-finished
		collected++
	}
}

func notOkCopy(err error) bool {
	return err != nil && !errors.Is(err, os.ErrDeadlineExceeded) && !errors.Is(err, syscall.EPIPE) && !errors.Is(err, syscall.ECONNRESET)
}
