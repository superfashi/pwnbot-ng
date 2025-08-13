package proxy

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

var (
	sourceIpv4    = net.IP{192, 168, 88, 88}
	rewrittenIpv4 = net.IP{192, 168, 88, 89}
	sourceIpv6    = net.IP{0x28, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88}
	rewrittenIpv6 = net.IP{0x28, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x89}
)

func createObfuscatorTun(logger *zap.Logger, isIpv6 bool) (*netlink.Tuntap, error) {
	link := &netlink.Tuntap{
		LinkAttrs: netlink.LinkAttrs{
			Name: "pwnbot-obf",
		},
		Mode:       unix.IFF_TUN,
		Flags:      unix.IFF_TUN_EXCL | unix.IFF_ONE_QUEUE | unix.IFF_NO_PI,
		Queues:     1,
		NonPersist: true,
	}
	if err := netlink.LinkAdd(link); err != nil {
		logger.Error("error creating tun device", zap.Error(err))
		return nil, err
	}
	if err := netlink.LinkSetUp(link); err != nil {
		logger.Error("error setting up tun device", zap.Error(err))
		return nil, err
	}

	var addr netlink.Addr
	if isIpv6 {
		addr.IPNet = &net.IPNet{
			IP:   sourceIpv6,
			Mask: net.CIDRMask(127, 128),
		}
	} else {
		addr.IPNet = &net.IPNet{
			IP:   sourceIpv4,
			Mask: net.CIDRMask(31, 32),
		}
	}

	if err := netlink.AddrAdd(link, &addr); err != nil {
		logger.Error("error adding address to tun device", zap.Error(err))
		return nil, err
	}

	return link, nil
}

func (p *Proxy) runObfuscator(stop <-chan struct{}, logger *zap.Logger, link *netlink.Tuntap) error {
	if len(link.Fds) != 1 {
		return errors.New("expected exactly one fd for tun device")
	}

	fd := link.Fds[0]

	obf := obfuscator{}

	p.wg.Add(1)
	go func() {
		defer p.wg.Done()

		buffer := make([]byte, 0x1000)

		for {
			n, err := fd.Read(buffer)
			if err != nil {
				if !errors.Is(err, os.ErrDeadlineExceeded) {
					logger.Error("error reading from tun device", zap.Error(err))
				}
				return
			}
			obf.processPacket(logger, fd, buffer[:n])
		}
	}()

	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		<-stop

		const stopWait = 5 * time.Second
		logger.Info("obfuscator stopped", zap.Stringer("wait", stopWait))
		if err := fd.SetReadDeadline(time.Now().Add(stopWait)); err != nil {
			logger.Error("error setting read deadline on tun fd", zap.Error(err))
		}
	}()

	return nil
}

var bufferPool = sync.Pool{
	New: func() interface{} {
		return gopacket.NewSerializeBuffer()
	},
}

func (o *obfuscator) processPacket(logger *zap.Logger, device io.Writer, data []byte) {
	if len(data) <= 0 {
		return
	}

	var packet gopacket.Packet
	var target netip.Addr
	var direction int8
	switch version := data[0] >> 4; version {
	case 4:
		packet = gopacket.NewPacket(data, layers.LayerTypeIPv4, gopacket.NoCopy)
		ipv4, ok := packet.NetworkLayer().(*layers.IPv4)
		if !ok {
			logger.Error("network layer is not IPv4")
			return
		}
		if ipv4.DstIP.Equal(rewrittenIpv4) {
			direction = -1
			ipv4.DstIP = sourceIpv4
			target = netip.AddrFrom4([4]byte(ipv4.SrcIP.To4()))
		} else if ipv4.SrcIP.Equal(sourceIpv4) {
			direction = 1
			ipv4.SrcIP = rewrittenIpv4
			target = netip.AddrFrom4([4]byte(ipv4.DstIP.To4()))
		}
	case 6:
		packet = gopacket.NewPacket(data, layers.LayerTypeIPv6, gopacket.NoCopy)
		ipv6, ok := packet.NetworkLayer().(*layers.IPv6)
		if !ok {
			logger.Error("network layer is not IPv6")
			return
		}
		if ipv6.DstIP.Equal(rewrittenIpv6) {
			direction = -1
			ipv6.DstIP = sourceIpv6
			target = netip.AddrFrom16([16]byte(ipv6.SrcIP.To16()))
		} else if ipv6.SrcIP.Equal(sourceIpv6) {
			direction = 1
			ipv6.SrcIP = rewrittenIpv6
			target = netip.AddrFrom16([16]byte(ipv6.DstIP.To16()))
		}
	default:
		logger.Warn("unknown IP packet version", zap.Uint8("version", version))
		return
	}

	if direction == 0 {
		// drop
		return
	}

	packets := o.obfuscate(packet, target, direction == 1)

	buffers := make([]gopacket.SerializeBuffer, 0, len(packets))
	for _, layers := range packets {
		buf := serializePacket(logger, layers...)
		if buf != nil {
			buffers = append(buffers, buf)
		}
	}

	for _, buffer := range buffers {
		if _, err := device.Write(buffer.Bytes()); err != nil {
			logger.Error("error writing to tun device", zap.Error(err))
		}
	}

	for _, buffer := range buffers {
		if err := buffer.Clear(); err != nil {
			logger.Error("error clearing serialize buffer", zap.Error(err))
		} else {
			bufferPool.Put(buffer)
		}
	}
}

func serializePacket(logger *zap.Logger, layers ...gopacket.Layer) gopacket.SerializeBuffer {
	netLayer, ok := layers[0].(gopacket.NetworkLayer)
	if !ok {
		logger.Error("first layer is not a network layer")
		return nil
	}

	for _, layer := range layers[1:] {
		type checksumSetter interface {
			SetNetworkLayerForChecksum(gopacket.NetworkLayer) error
		}
		if need, ok := layer.(checksumSetter); ok {
			if err := need.SetNetworkLayerForChecksum(netLayer); err != nil {
				logger.Error("error setting network layer for TCP checksum", zap.Error(err))
				continue
			}
		}
	}

	serLayers := make([]gopacket.SerializableLayer, 0, len(layers))
	for _, layer := range layers {
		sl, ok := layer.(gopacket.SerializableLayer)
		if !ok {
			logger.Error("layer is not serializable")
			return nil
		}
		serLayers = append(serLayers, sl)
	}

	buf := bufferPool.Get().(gopacket.SerializeBuffer)
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}, serLayers...); err != nil {
		logger.Error("error serializing packet", zap.Error(err))
		return nil
	}

	return buf
}

type obfuscator struct{}

func (o *obfuscator) obfuscate(packet gopacket.Packet, target netip.Addr, outbound bool) [][]gopacket.Layer {
	// implement obfuscation logic here
	return [][]gopacket.Layer{packet.Layers()}
}
