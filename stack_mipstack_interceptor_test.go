package tun

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/sing/common/buf"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

// testInterceptor records the packets it is offered. When match is nil every
// destination is offered (the PacketInterceptor-without-matcher case).
type testInterceptor struct {
	mu       sync.Mutex
	packets  [][]byte
	consume  bool
	match    func(netip.Addr) bool
	mutating bool
}

func (i *testInterceptor) InterceptPacket(_ netip.Addr, packet []byte) bool {
	i.mu.Lock()
	i.packets = append(i.packets, append([]byte(nil), packet...))
	i.mu.Unlock()
	if i.mutating {
		// Overlay source rewriting mutates the buffer it is handed; the stack
		// must not be handing out its own reusable read buffer.
		for index := range packet {
			packet[index] = 0xff
		}
	}
	return i.consume
}

func (i *testInterceptor) seen() int {
	i.mu.Lock()
	defer i.mu.Unlock()
	return len(i.packets)
}

// testMatchingInterceptor also implements PacketInterceptMatcher.
type testMatchingInterceptor struct {
	testInterceptor
}

func (i *testMatchingInterceptor) ShouldInterceptPacket(destination netip.Addr) bool {
	if i.match == nil {
		return true
	}
	return i.match(destination)
}

func TestMipsPacketInterceptorConsumesPacket(t *testing.T) {
	device := newMemoryTun()
	source, target := netip.MustParseAddr("198.18.0.1"), netip.MustParseAddr("8.8.8.8")
	handled := make(chan struct{}, 1)
	handler := &testHandler{udp: func(_ context.Context, _ netip.AddrPort, b *buf.Buffer, _ M.Metadata, _ func(N.PacketConn) N.PacketWriter) {
		b.Release()
		select {
		case handled <- struct{}{}:
		default:
		}
	}}
	interceptor := &testInterceptor{consume: true, mutating: true}
	testStack(t, device, handler, func(options *StackOptions) {
		options.PacketInterceptor = interceptor
	})

	device.in <- udpPacket(source, target, 443, []byte("intercepted"))

	deadline := time.After(2 * time.Second)
	for interceptor.seen() == 0 {
		select {
		case <-handled:
			t.Fatal("consumed packet still reached the handler")
		case <-deadline:
			t.Fatal("interceptor was never offered the packet")
		case <-time.After(10 * time.Millisecond):
		}
	}
	select {
	case <-handled:
		t.Fatal("consumed packet still reached the handler")
	case <-time.After(200 * time.Millisecond):
	}
}

func TestMipsPacketInterceptorPassThrough(t *testing.T) {
	device := newMemoryTun()
	source, target := netip.MustParseAddr("198.18.0.1"), netip.MustParseAddr("8.8.8.8")
	handled := make(chan error, 1)
	handler := &testHandler{udp: func(_ context.Context, _ netip.AddrPort, b *buf.Buffer, m M.Metadata, _ func(N.PacketConn) N.PacketWriter) {
		b.Release()
		if m.Destination.Addr != target {
			handled <- errors.New("incorrect destination")
			return
		}
		handled <- nil
	}}
	// consume=false means "not mine" -- the packet must continue into the stack.
	interceptor := &testInterceptor{consume: false}
	testStack(t, device, handler, func(options *StackOptions) {
		options.PacketInterceptor = interceptor
	})

	device.in <- udpPacket(source, target, 443, []byte("passed through"))

	select {
	case err := <-handled:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("packet never reached the handler")
	}
	if interceptor.seen() != 1 {
		t.Fatalf("interceptor offered %d packets, want 1", interceptor.seen())
	}
}

func TestMipsPacketInterceptorRespectsMatcher(t *testing.T) {
	device := newMemoryTun()
	source, target := netip.MustParseAddr("198.18.0.1"), netip.MustParseAddr("8.8.8.8")
	handled := make(chan struct{}, 1)
	handler := &testHandler{udp: func(_ context.Context, _ netip.AddrPort, b *buf.Buffer, _ M.Metadata, _ func(N.PacketConn) N.PacketWriter) {
		b.Release()
		select {
		case handled <- struct{}{}:
		default:
		}
	}}
	interceptor := &testMatchingInterceptor{}
	// Only 100.96.0.0/11-style overlay traffic is claimed; 8.8.8.8 is not.
	interceptor.consume = true
	interceptor.match = func(destination netip.Addr) bool {
		return netip.MustParsePrefix("100.96.0.0/11").Contains(destination)
	}
	testStack(t, device, handler, func(options *StackOptions) {
		options.PacketInterceptor = interceptor
	})

	device.in <- udpPacket(source, target, 443, []byte("not overlay"))

	select {
	case <-handled:
	case <-time.After(3 * time.Second):
		t.Fatal("non-matching packet was not delivered to the stack")
	}
	if interceptor.seen() != 0 {
		t.Fatalf("interceptor was offered %d packets despite its matcher, want 0", interceptor.seen())
	}
}
