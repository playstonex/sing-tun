//go:build with_gvisor

package tun

import (
	"testing"

	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/link/channel"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/tcp"
)

// TestGVisorTCPWindowOverride answers step 3/4 of
// docs/TUN_STACK_OPTIMIZATION.md for real, against gVisor's own API, not a
// mock: does NewGVisorStackWithOptions actually raise the TCP receive/send
// buffer ceiling when told to, and does 0 still reproduce the historical
// 20KB default unchanged? Uses channel.New, the same in-process gVisor
// endpoint stack_mixed.go's Mixed.Start already builds one from, so this
// exercises the real gvisor/pkg/tcpip/stack.Stack rather than a fake.
func TestGVisorTCPWindowOverride(t *testing.T) {
	tests := []struct {
		name       string
		override   int
		wantWindow int
	}{
		{"zero uses the 20KB default", 0, 20 * 1024},
		{"explicit override raises the ceiling", 256 * 1024, 256 * 1024},
		{"override can also lower it", 4 * 1024, 4 * 1024},
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
			if receiveOpt.Default != tt.wantWindow || receiveOpt.Max != tt.wantWindow {
				t.Fatalf("receive window = {Default:%d Max:%d}, want both %d", receiveOpt.Default, receiveOpt.Max, tt.wantWindow)
			}

			var sendOpt tcpip.TCPSendBufferSizeRangeOption
			if err := ipStack.TransportProtocolOption(tcp.ProtocolNumber, &sendOpt); err != nil {
				t.Fatalf("read TCPSendBufferSizeRangeOption: %v", err)
			}
			if sendOpt.Default != tt.wantWindow || sendOpt.Max != tt.wantWindow {
				t.Fatalf("send window = {Default:%d Max:%d}, want both %d", sendOpt.Default, sendOpt.Max, tt.wantWindow)
			}

			// Max must equal the override, not just Default -- otherwise
			// TCPModerateReceiveBufferOption's auto-tuning would grow back
			// down to the historical 20KB ceiling regardless of what the
			// caller asked for. This is the exact bug this test would catch
			// if someone "simplified" the fix to only touch Default.
			if receiveOpt.Max != tt.wantWindow {
				t.Fatalf("Max ceiling = %d, want %d -- auto-tuning would not honor the override", receiveOpt.Max, tt.wantWindow)
			}
		})
	}
}
