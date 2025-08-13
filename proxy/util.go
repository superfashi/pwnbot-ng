package proxy

import (
	"context"
	"math"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/cockroachdb/crlib/fifo"
	"go.uber.org/zap"
)

func prefixToIpNet(prefix netip.Prefix) *net.IPNet {
	addr := prefix.Addr()
	bits := prefix.Bits()

	ip := net.IP(addr.AsSlice())

	var mask net.IPMask
	if addr.Is4() {
		mask = net.CIDRMask(bits, 32)
	} else {
		mask = net.CIDRMask(bits, 128)
	}

	return &net.IPNet{
		IP:   ip,
		Mask: mask,
	}
}

func getSockOpt[T any](sockFd, level, optName uintptr, opt *T) error {
	type sockLen = uint32
	optLen := sockLen(unsafe.Sizeof(*opt))
	_, _, e := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT, sockFd, level, optName,
		uintptr(unsafe.Pointer(opt)), uintptr(unsafe.Pointer(&optLen)), 0)
	if e != 0 {
		return e
	}
	return nil
}

type PreAllocator struct {
	logger    *zap.Logger
	count     int64
	allocated *fifo.Semaphore
	limit     *fifo.Semaphore
}

func (p *PreAllocator) transfer() bool {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if p.allocated.Acquire(ctx, 1) == nil {
		return true
	}
	p.logger.Warn("used more connections than allocated")
	return false
}

func (p *PreAllocator) put() {
	p.allocated.Release(1)
}

func (p *PreAllocator) ReleaseAll() {
	if p.limit != nil {
		p.limit.Release(p.count)
	}
}

type circuitBreaker struct {
	lock   sync.Mutex
	retry  uint
	cancel context.CancelFunc
}

func (c *circuitBreaker) trip() {
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.retry == 0 {
		c.retry = 1
	}
}

func (c *circuitBreaker) reset(logger *zap.Logger) {
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.retry > 0 {
		logger.Debug("circuit breaker reset")

		c.retry = 0
		if c.cancel != nil {
			c.cancel()
		}
	}
}

func (c *circuitBreaker) backoff(ctx context.Context, logger *zap.Logger) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	retry := func() uint {
		c.lock.Lock()
		defer c.lock.Unlock()
		if c.retry == 0 {
			return 0
		}
		if c.cancel != nil {
			logger.DPanic("concurrent access")
		}
		c.cancel = cancel
		ret := c.retry
		c.retry++
		return ret
	}()
	if retry == 0 {
		return
	}

	backoff := time.Duration(math.Pow(1.45, float64(retry-1)) * 5 * float64(time.Second))
	// 5s, 7.25s, 10.5s, 15.2s, 22.1s, 32.0s, 46.5s, 67.4s, 97.7s, ...

	logger.Debug("circuit breaker backoff", zap.Stringer("duration", backoff), zap.Uint("retry", retry))

	select {
	case <-ctx.Done():
	case <-time.After(backoff):
	}

	c.lock.Lock()
	defer c.lock.Unlock()
	c.cancel = nil
}
