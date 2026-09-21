//go:build with_gvisor

package tun

import (
	"testing"

	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/link/channel"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/tcp"
)

// TestGVisorTCPWindowOverride checks the receive/send window configuration
// against gVisor's own API, using channel.New -- the same in-process endpoint
// Mixed.Start builds one from -- so this exercises the real
// gvisor/pkg/tcpip/stack.Stack rather than a mock.
//
// The contract under test CHANGED, and the reason is worth stating because the
// previous version of this test actively asserted the bug. It required
// Default == Max == override, on the belief that Max had to match or auto-tuning
// would grow back down to 20 KB. Equal values do not make auto-tuning honour a
// ceiling -- they leave it nothing to tune, because
// TCPModerateReceiveBufferOption grows a connection BETWEEN Default and Max.
// Pinning both forced a choice between two measured failures on iOS: 32 KB for
// every one of 208 concurrent connections took the Network Extension to a 47 MB
// footprint and a SIGKILL, while 20 KB survived and collapsed throughput to
// 3.37 Mbps (20 KB / 150 ms RTT = 1.09 Mbps per connection, three active).
//
// So Default is now the fixed starting size every connection gets, and the
// override is the CEILING the few bulk transfers may grow into.
func TestGVisorTCPWindowOverride(t *testing.T) {
	const initialWindow = 20 * 1024
	const defaultMaxWindow = 512 * 1024

	tests := []struct {
		name        string
		override    int
		wantDefault int
		wantMax     int
	}{
		// The unset case must still have growth room. Inheriting the start size
		// here is precisely the 3.37 Mbps configuration, and it would be the
		// out-of-box one.
		{"zero starts at 20KB with a real ceiling", 0, initialWindow, defaultMaxWindow},
		{"an override sets the CEILING and leaves the start alone", 2 * 1024 * 1024, initialWindow, 2 * 1024 * 1024},
		{"an override can lower the ceiling below the default", 128 * 1024, initialWindow, 128 * 1024},
		// A ceiling at or below the starting size would be incoherent -- gVisor
		// would have a Default it is not allowed to reach -- so these fall back
		// to the default ceiling rather than pinning growth off.
		{"an override equal to the start size falls back to the default ceiling", initialWindow, initialWindow, defaultMaxWindow},
		{"an override below the start size falls back to the default ceiling", 4 * 1024, initialWindow, defaultMaxWindow},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			endpoint := channel.New(64, 1500, "")
			ipStack, err := NewGVisorStackWithOptions(endpoint, stack.NICOptions{}, tt.override)
			if err != nil {
				t.Fatalf("NewGVisorStackWithOptions: %v", err)
			}
			defer ipStack.Close()

			var receiveOpt tcpip.TCPReceiveBufferSizeRangeOption
			if err := ipStack.TransportProtocolOption(tcp.ProtocolNumber, &receiveOpt); err != nil {
				t.Fatalf("read TCPReceiveBufferSizeRangeOption: %v", err)
			}
			if receiveOpt.Default != tt.wantDefault {
				t.Errorf("receive Default = %d, want %d (the size every connection starts at)",
					receiveOpt.Default, tt.wantDefault)
			}
			if receiveOpt.Max != tt.wantMax {
				t.Errorf("receive Max = %d, want %d (the ceiling auto-tuning may grow into)",
					receiveOpt.Max, tt.wantMax)
			}

			var sendOpt tcpip.TCPSendBufferSizeRangeOption
			if err := ipStack.TransportProtocolOption(tcp.ProtocolNumber, &sendOpt); err != nil {
				t.Fatalf("read TCPSendBufferSizeRangeOption: %v", err)
			}
			if sendOpt.Default != tt.wantDefault {
				t.Errorf("send Default = %d, want %d", sendOpt.Default, tt.wantDefault)
			}
			if sendOpt.Max != tt.wantMax {
				t.Errorf("send Max = %d, want %d", sendOpt.Max, tt.wantMax)
			}
		})
	}
}

// The split is only useful if the tuner that consumes it is on. Without this,
// a future change could disable moderation and every connection would sit at
// Default forever -- which is the 3.37 Mbps failure, reached silently while the
// range option still looked correctly configured.
func TestGVisorReceiveBufferModerationIsEnabled(t *testing.T) {
	endpoint := channel.New(64, 1500, "")
	ipStack, err := NewGVisorStackWithOptions(endpoint, stack.NICOptions{}, 512*1024)
	if err != nil {
		t.Fatalf("NewGVisorStackWithOptions: %v", err)
	}
	defer ipStack.Close()

	var moderate tcpip.TCPModerateReceiveBufferOption
	if err := ipStack.TransportProtocolOption(tcp.ProtocolNumber, &moderate); err != nil {
		t.Fatalf("read TCPModerateReceiveBufferOption: %v", err)
	}
	if !moderate {
		t.Error("TCPModerateReceiveBufferOption is false; nothing will grow a connection " +
			"from Default toward Max, so the raised ceiling is unreachable")
	}
}

// A ceiling that does not exceed the starting size cannot produce any growth,
// so this pins the relationship rather than the numbers: it fails if someone
// makes Default track the override again.
func TestWindowCeilingExceedsTheStartingSize(t *testing.T) {
	endpoint := channel.New(64, 1500, "")
	ipStack, err := NewGVisorStackWithOptions(endpoint, stack.NICOptions{}, 512*1024)
	if err != nil {
		t.Fatalf("NewGVisorStackWithOptions: %v", err)
	}
	defer ipStack.Close()

	var receiveOpt tcpip.TCPReceiveBufferSizeRangeOption
	if err := ipStack.TransportProtocolOption(tcp.ProtocolNumber, &receiveOpt); err != nil {
		t.Fatalf("read TCPReceiveBufferSizeRangeOption: %v", err)
	}
	if receiveOpt.Max <= receiveOpt.Default {
		t.Errorf("Max (%d) does not exceed Default (%d) for a 512 KB override; "+
			"auto-tuning has no room and every connection is pinned at the start size",
			receiveOpt.Max, receiveOpt.Default)
	}
}
