// Package tun benchmark for step 4 of docs/TUN_STACK_OPTIMIZATION.md: is
// mipstack's per-connection buffer capacity (tcpReceiveCapacity=1MB,
// tcpSendCapacity=256KB in github.com/metacubex/mipstack's tcp.go) an eager
// allocation at accept time, or a ceiling the connection grows into?
//
// This matters because mihomo caps the Go heap at 40MB on iOS
// (mate/service.go). If mipstack allocated its full capacity per connection
// up front, roughly 40 concurrent connections would exhaust that heap.
//
// Run: go test -tags with_gvisor -run NONE -bench BenchmarkMipstack -benchmem .
package tun

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"testing"
	"time"

	"github.com/metacubex/sing/common/logger"
	M "github.com/metacubex/sing/common/metadata"
)

// BenchmarkMipstackIdleConnAllocs measures allocations for completing one TCP
// handshake and immediately closing -- no application data. If mipstack
// pre-allocated tcpReceiveCapacity/tcpSendCapacity (1MB/256KB) per connection
// at accept time, b.AllocedBytesPerOp would report at least that many bytes
// per iteration. Reading the source says it does not: newTCPConn (tcp.go:4393)
// stores receiveCapacity/sendCapacity as plain int ceilings, and the segment
// queue (newTCPSegmentQueue, tcp.go:913) allocates only a notification
// channel. Actual byte storage is allocated on demand by tcpSendBuffer.append
// (tcp.go:3481) as data is written, in bounded chunks -- never the full
// capacity up front. This benchmark makes that an empirical, reproducible
// number instead of only a reading of the source.
func BenchmarkMipstackIdleConnAllocs(b *testing.B) {
	d := newMemoryTun()
	source, target := netip.MustParseAddr("198.18.0.1"), netip.MustParseAddr("8.8.8.8")
	accepted := make(chan net.Conn, 1)
	release := make(chan struct{})
	h := &testHandler{tcp: func(_ context.Context, c net.Conn, _ M.Metadata) error {
		accepted <- c
		<-release
		return nil
	}}
	s := benchTestStack(b, d, h, nil)
	defer s.Close()

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		srcPort := uint16(20000 + i%40000)
		d.in <- tcpSynPacket(source, target, srcPort, 100)
		synAck := benchReadPacket(b, d)
		ack := beUint32(synAck[20+4:]) + 1
		d.in <- tcpAckPacket(source, target, srcPort, 101, ack) // handshake complete
		select {
		case conn := <-accepted:
			conn.Close()
		case <-time.After(10 * time.Second):
			b.Fatal("connection never reached the handler")
		}
		// conn.Close() makes mipstack emit its own FIN asynchronously onto
		// d.out. Drain it now, or the next iteration's synack read sees this
		// stale FIN instead -- confirmed by hand with a standalone repro
		// (drained packet is 40 bytes, flags 0x11 = FIN+ACK, versus the SYN-ACK's
		// 44 bytes / 0x12).
		select {
		case <-d.out:
		case <-time.After(200 * time.Millisecond):
		}
	}
	close(release)
}

// BenchmarkMipstackConnMemoryFootprint reports heap growth per N concurrent
// idle accepted connections (held open, never closed until the sub-benchmark
// ends), extrapolated to a per-connection byte cost. That number is the
// direct answer to the OOM question: a few KB (queue + bookkeeping structs)
// versus the 1MB/256KB capacity ceiling that a naive reading of the constants
// would suggest.
func BenchmarkMipstackConnMemoryFootprint(b *testing.B) {
	for _, n := range []int{1, 10, 40, 100} {
		b.Run(fmt.Sprintf("conns=%d", n), func(b *testing.B) {
			d := newMemoryTun()
			source := netip.MustParseAddr("198.18.0.1")
			release := make(chan struct{})
			defer close(release)
			h := &testHandler{tcp: func(_ context.Context, c net.Conn, _ M.Metadata) error {
				<-release
				return nil
			}}
			s := benchTestStack(b, d, h, nil)
			defer s.Close()

			runtime.GC()
			var before runtime.MemStats
			runtime.ReadMemStats(&before)

			seq := uint32(100)
			for i := 0; i < n; i++ {
				// Vary the destination so each handshake opens a distinct
				// connection rather than being coalesced by the 4-tuple.
				target := netip.AddrFrom4([4]byte{8, 8, 8, byte(i % 250)})
				seq++
				d.in <- tcpPacket(source, target, seq, 0, 2, nil)
				synAck := benchReadPacket(b, d)
				ack := beUint32(synAck[20+4:]) + 1
				seq++
				d.in <- tcpPacket(source, target, seq, ack, 16, nil)
			}
			// Give the handler goroutines a moment to actually reach the
			// blocking receive on `release` before measuring -- otherwise
			// the connections may still be mid-setup.
			time.Sleep(50 * time.Millisecond)

			runtime.GC()
			var after runtime.MemStats
			runtime.ReadMemStats(&after)

			grown := int64(after.HeapAlloc) - int64(before.HeapAlloc)
			var perConn float64
			if n > 0 {
				perConn = float64(grown) / float64(n)
			}
			b.ReportMetric(perConn, "bytes/conn")
			b.ReportMetric(float64(grown), "heap-bytes-total")
		})
	}
}

// benchTestStack mirrors testStack (stack_mipstack_test.go) but takes a
// *testing.B.
// tcpSynPacket and tcpAckPacket build minimal SYN / pure-ACK segments with an
// explicit source port, unlike the shared tcpPacket test helper (which
// hardcodes port 12345 for every packet). Each benchmark iteration needs its
// own 4-tuple: reusing one lets a closed connection's TIME_WAIT-equivalent
// teardown state block the next iteration's SYN, which is a real bug this
// benchmark hit on its first run, not benchmark flakiness.
func tcpSynPacket(source, target netip.Addr, srcPort uint16, seq uint32) []byte {
	p := make([]byte, 20)
	binary.BigEndian.PutUint16(p, srcPort)
	binary.BigEndian.PutUint16(p[2:], 443)
	binary.BigEndian.PutUint32(p[4:], seq)
	p[12] = 5 << 4
	p[13] = 2 // SYN
	binary.BigEndian.PutUint16(p[14:], 65535)
	return transportPacket(source, target, 6, p)
}

func tcpAckPacket(source, target netip.Addr, srcPort uint16, seq, ack uint32) []byte {
	p := make([]byte, 20)
	binary.BigEndian.PutUint16(p, srcPort)
	binary.BigEndian.PutUint16(p[2:], 443)
	binary.BigEndian.PutUint32(p[4:], seq)
	binary.BigEndian.PutUint32(p[8:], ack)
	p[12] = 5 << 4
	p[13] = 16 // ACK
	binary.BigEndian.PutUint16(p[14:], 65535)
	return transportPacket(source, target, 6, p)
}

func benchTestStack(b *testing.B, device Tun, handler *testHandler, modify func(*StackOptions)) *Mipstack {
	b.Helper()
	options := StackOptions{Logger: logger.NOP(), Tun: device, Handler: handler, Context: context.Background(), ICMPTimeout: 50 * time.Millisecond,
		TunOptions: Options{MTU: 1500, Inet4Address: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/30")}, Inet6Address: []netip.Prefix{netip.MustParsePrefix("fd00::1/126")}}}
	if modify != nil {
		modify(&options)
	}
	v, err := NewStack("mips", options)
	if err != nil {
		b.Fatal(err)
	}
	s := v.(*Mipstack)
	if err = s.Start(); err != nil {
		b.Fatal(err)
	}
	return s
}

func benchReadPacket(b *testing.B, d *memoryTun) []byte {
	b.Helper()
	select {
	case p := <-d.out:
		return p
	case <-time.After(10 * time.Second):
		b.Fatal("timed out waiting for TUN response")
		return nil
	}
}

func beUint32(p []byte) uint32 {
	return uint32(p[0])<<24 | uint32(p[1])<<16 | uint32(p[2])<<8 | uint32(p[3])
}
