//go:build with_gvisor

package tun

import (
	"context"
	"net/netip"
	"time"

	E "github.com/metacubex/sing/common/exceptions"
	"github.com/metacubex/sing/common/logger"

	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/network/ipv4"
	"github.com/metacubex/gvisor/pkg/tcpip/network/ipv6"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/icmp"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/tcp"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/udp"
)

const WithGVisor = true

const DefaultNIC tcpip.NICID = 1

type GVisor struct {
	ctx                  context.Context
	tun                  GVisorTun
	inet4Address         netip.Addr
	inet6Address         netip.Addr
	inet4LoopbackAddress []netip.Addr
	inet6LoopbackAddress []netip.Addr
	udpTimeout           time.Duration
	icmpTimeout          time.Duration
	broadcastAddr        netip.Addr
	handler              Handler
	logger               logger.Logger
	packetInterceptor    PacketInterceptor
	tcpWindowBytes       int
	stack                *stack.Stack
	endpoint             stack.LinkEndpoint
}

type GVisorTun interface {
	Tun
	WritePacket(pkt *stack.PacketBuffer) (int, error)
	NewEndpoint() (stack.LinkEndpoint, stack.NICOptions, error)
}

func NewGVisor(
	options StackOptions,
) (Stack, error) {
	gTun, isGTun := options.Tun.(GVisorTun)
	if !isGTun {
		return nil, E.New("gVisor stack is unsupported on current platform")
	}

	var (
		inet4Address netip.Addr
		inet6Address netip.Addr
	)
	if len(options.TunOptions.Inet4Address) > 0 {
		inet4Address = options.TunOptions.Inet4Address[0].Addr()
	}
	if len(options.TunOptions.Inet6Address) > 0 {
		inet6Address = options.TunOptions.Inet6Address[0].Addr()
	}

	gStack := &GVisor{
		ctx:                  options.Context,
		tun:                  gTun,
		inet4Address:         inet4Address,
		inet6Address:         inet6Address,
		inet4LoopbackAddress: options.TunOptions.Inet4LoopbackAddress,
		inet6LoopbackAddress: options.TunOptions.Inet6LoopbackAddress,
		udpTimeout:           options.UDPTimeout,
		icmpTimeout:          options.ICMPTimeout,
		broadcastAddr:        BroadcastAddr(options.TunOptions.Inet4Address),
		handler:              options.Handler,
		logger:               options.Logger,
		packetInterceptor:    options.PacketInterceptor,
		tcpWindowBytes:       options.TCPWindowBytes,
	}
	return gStack, nil
}

func (t *GVisor) Start() error {
	linkEndpoint, nicOptions, err := t.tun.NewEndpoint()
	if err != nil {
		return err
	}
	linkEndpoint = &LinkEndpointFilter{
		LinkEndpoint:     linkEndpoint,
		BroadcastAddress: t.broadcastAddr,
		Writer:           t.tun,
		Interceptor:      t.packetInterceptor,
	}
	ipStack, err := NewGVisorStackWithOptions(linkEndpoint, nicOptions, t.tcpWindowBytes)
	if err != nil {
		return err
	}
	ipStack.SetTransportProtocolHandler(tcp.ProtocolNumber, NewTCPForwarderWithLoopback(t.ctx, ipStack, t.handler, t.inet4LoopbackAddress, t.inet6LoopbackAddress, t.tun).HandlePacket)
	ipStack.SetTransportProtocolHandler(udp.ProtocolNumber, NewUDPForwarder(t.ctx, ipStack, t.handler).HandlePacket)
	icmpForwarder := NewICMPForwarder(t.ctx, ipStack, t.inet4Address, t.inet6Address, t.handler, t.icmpTimeout)
	ipStack.SetTransportProtocolHandler(icmp.ProtocolNumber4, icmpForwarder.HandlePacket)
	ipStack.SetTransportProtocolHandler(icmp.ProtocolNumber6, icmpForwarder.HandlePacket)
	t.stack = ipStack
	t.endpoint = linkEndpoint
	return nil
}

func (t *GVisor) Close() error {
	if t.stack == nil {
		return nil
	}
	t.endpoint.Attach(nil)
	t.stack.Close()
	for _, endpoint := range t.stack.CleanupEndpoints() {
		endpoint.Abort()
	}
	return nil
}

func AddressFromAddr(destination netip.Addr) tcpip.Address {
	if destination.Is6() {
		return tcpip.AddrFrom16(destination.As16())
	} else {
		return tcpip.AddrFrom4(destination.As4())
	}
}

func AddrFromAddress(address tcpip.Address) netip.Addr {
	if address.Len() == 16 {
		return netip.AddrFrom16(address.As16())
	} else {
		return netip.AddrFrom4(address.As4())
	}
}

func NewGVisorStack(ep stack.LinkEndpoint) (*stack.Stack, error) {
	return NewGVisorStackWithOptions(ep, stack.NICOptions{}, 0)
}

func NewGVisorStackWithOptions(ep stack.LinkEndpoint, opts stack.NICOptions, tcpWindowBytes int) (*stack.Stack, error) {
	ipStack := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			ipv6.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
			icmp.NewProtocol4,
			icmp.NewProtocol6,
		},
	})
	err := ipStack.CreateNICWithOptions(DefaultNIC, ep, opts)
	if err != nil {
		return nil, gonet.TranslateNetstackError(err)
	}
	ipStack.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: DefaultNIC},
		{Destination: header.IPv6EmptySubnet, NIC: DefaultNIC},
	})
	ipStack.SetSpoofing(DefaultNIC, true)
	ipStack.SetPromiscuousMode(DefaultNIC, true)
	// Default and Max are DELIBERATELY DIFFERENT, and that distinction is the
	// whole point of this block.
	//
	// They used to be equal, which neutered TCPModerateReceiveBufferOption
	// below: auto-tuning grows a connection's buffer between Default and Max,
	// so setting them to one value pins every connection at that value and the
	// tuner has nowhere to go. That forced a choice between two failures, and
	// both were observed on iOS in one afternoon:
	//
	//   - equal and large (32 KB): 208 concurrent connections during a
	//     speedtest took the Network Extension's footprint to 47 MB and the
	//     kernel SIGKILLed it for memory.
	//   - equal and small (20 KB): survived, and collapsed to 3.4 Mbps.
	//     Single-connection throughput is window/RTT, and 20 KB over the
	//     ~150 ms path to the proxy is 1.09 Mbps per connection -- three
	//     active connections measured 3.37 Mbps, which is that arithmetic.
	//
	// Separating them dissolves the trade-off instead of choosing a side. The
	// figure that buys throughput is the TOTAL window across connections
	// divided by RTT: 100 Mbps at 150 ms needs 1.875 MB in flight IN
	// AGGREGATE, which is cheap. What was expensive was reserving the ceiling
	// for every connection whether it had data or not.
	//
	// So Default stays at sing-tun's long-standing 20 KB -- every connection
	// starts there, and the hundreds of short-lived ones a browser opens stay
	// there -- while Max is the ceiling the handful of bulk transfers may grow
	// into. Memory then tracks what is actually in flight, which the real
	// path's bandwidth-delay product already bounds.
	//
	// The UNSET case gets a real ceiling rather than inheriting the start size.
	// Leaving Max at 20 KB when no override is given would make the default
	// configuration the 3.37 Mbps one, which is how this stack behaved for its
	// whole history: the 20 KB pin was never a memory decision, it was an
	// unexamined default that happened to also cap throughput at 20 KB / RTT.
	const initialWindowBytes = 20 * 1024
	const defaultMaxWindowBytes = 512 * 1024
	maxWindowBytes := defaultMaxWindowBytes
	if tcpWindowBytes > initialWindowBytes {
		maxWindowBytes = tcpWindowBytes
	}
	ipStack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpip.TCPReceiveBufferSizeRangeOption{
		Min:     1,
		Default: initialWindowBytes,
		Max:     maxWindowBytes,
	})
	ipStack.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpip.TCPSendBufferSizeRangeOption{
		Min:     1,
		Default: initialWindowBytes,
		Max:     maxWindowBytes,
	})
	sOpt := tcpip.TCPSACKEnabled(true)
	ipStack.SetTransportProtocolOption(tcp.ProtocolNumber, &sOpt)
	mOpt := tcpip.TCPModerateReceiveBufferOption(true)
	ipStack.SetTransportProtocolOption(tcp.ProtocolNumber, &mOpt)
	return ipStack, nil
}
