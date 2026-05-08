//go:build with_gvisor

package tun

import (
	"net/netip"

	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
)

var _ stack.LinkEndpoint = (*LinkEndpointFilter)(nil)

type LinkEndpointFilter struct {
	stack.LinkEndpoint
	BroadcastAddress netip.Addr
	Writer           GVisorTun
	Interceptor      PacketInterceptor
}

func (w *LinkEndpointFilter) Attach(dispatcher stack.NetworkDispatcher) {
	w.LinkEndpoint.Attach(&networkDispatcherFilter{
		NetworkDispatcher: dispatcher,
		broadcastAddress:  w.BroadcastAddress,
		writer:            w.Writer,
		interceptor:       w.Interceptor,
	})
}

var _ stack.NetworkDispatcher = (*networkDispatcherFilter)(nil)

type networkDispatcherFilter struct {
	stack.NetworkDispatcher
	broadcastAddress netip.Addr
	writer           GVisorTun
	interceptor      PacketInterceptor
}

func (w *networkDispatcherFilter) DeliverNetworkPacket(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	var network header.Network
	if protocol == header.IPv4ProtocolNumber {
		if headerPackets, loaded := pkt.Data().PullUp(header.IPv4MinimumSize); loaded {
			network = header.IPv4(headerPackets)
		}
	} else {
		if headerPackets, loaded := pkt.Data().PullUp(header.IPv6MinimumSize); loaded {
			network = header.IPv6(headerPackets)
		}
	}
	if network == nil {
		w.NetworkDispatcher.DeliverNetworkPacket(protocol, pkt)
		return
	}
	destination := AddrFromAddress(network.DestinationAddress())
	if destination == w.broadcastAddress || !destination.IsGlobalUnicast() {
		w.writer.WritePacket(pkt)
		return
	}
	if shouldInterceptPacket(w.interceptor, destination) {
		packet := packetBufferBytes(pkt)
		if len(packet) > 0 && w.interceptor.InterceptPacket(destination, packet) {
			return
		}
	}
	w.NetworkDispatcher.DeliverNetworkPacket(protocol, pkt)
}

func shouldInterceptPacket(interceptor PacketInterceptor, destination netip.Addr) bool {
	if interceptor == nil {
		return false
	}
	matcher, hasMatcher := interceptor.(PacketInterceptMatcher)
	return !hasMatcher || matcher.ShouldInterceptPacket(destination)
}

func packetBufferBytes(pkt *stack.PacketBuffer) []byte {
	views := pkt.AsSlices()
	if len(views) == 0 {
		return nil
	}
	if len(views) == 1 {
		return append([]byte(nil), views[0]...)
	}

	total := 0
	for _, view := range views {
		total += len(view)
	}
	packet := make([]byte, 0, total)
	for _, view := range views {
		packet = append(packet, view...)
	}
	return packet
}
