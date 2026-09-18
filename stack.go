package tun

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"time"

	"github.com/metacubex/sing/common/control"
	E "github.com/metacubex/sing/common/exceptions"
	"github.com/metacubex/sing/common/logger"
)

var (
	ErrDrop  = E.New("drop by rule")
	ErrReset = E.New("reset by rule")
)

type Stack interface {
	Start() error
	Close() error
}

type PacketInterceptor interface {
	InterceptPacket(destination netip.Addr, packet []byte) bool
}

type PacketInterceptMatcher interface {
	ShouldInterceptPacket(destination netip.Addr) bool
}

// shouldInterceptPacket reports whether the interceptor wants to inspect a
// packet bound for destination. A nil interceptor never intercepts; an
// interceptor without a matcher inspects every packet.
func shouldInterceptPacket(interceptor PacketInterceptor, destination netip.Addr) bool {
	if interceptor == nil {
		return false
	}
	matcher, hasMatcher := interceptor.(PacketInterceptMatcher)
	return !hasMatcher || matcher.ShouldInterceptPacket(destination)
}

type StackOptions struct {
	Context                context.Context
	Tun                    Tun
	TunOptions             Options
	EndpointIndependentNat bool
	UDPTimeout             time.Duration
	ICMPTimeout            time.Duration
	Handler                Handler
	Logger                 logger.Logger
	ForwarderBindInterface bool
	IncludeAllNetworks     bool
	InterfaceFinder        control.InterfaceFinder
	EnforceBindInterface   bool
	PacketInterceptor      PacketInterceptor
	// TCPWindowBytes overrides the gVisor stack's fixed TCP receive/send
	// buffer size (default 20*1024, stack_gvisor.go's NewGVisorStackWithOptions).
	// 0 keeps that default. See docs/TUN_STACK_OPTIMIZATION.md step 3/4 in the
	// mihomo/Violet repo for the throughput-bound arithmetic (throughput ≈
	// window / RTT) behind why this exists: the fixed 20KB caps single-connection
	// throughput well below what a real network path allows once RTT grows past
	// a few milliseconds, and TCPModerateReceiveBufferOption's auto-tuning has
	// no room to grow past a ceiling that equals its own floor.
	TCPWindowBytes int
}

func NewStack(
	stack string,
	options StackOptions,
) (Stack, error) {
	switch stack {
	case "":
		if options.IncludeAllNetworks {
			return NewGVisor(options)
		} else if WithGVisor && !options.TunOptions.GSO {
			return NewMixed(options)
		} else {
			return NewSystem(options)
		}
	case "mips":
		return NewMipstack(options)
	case "gvisor":
		return NewGVisor(options)
	case "mixed":
		if options.IncludeAllNetworks {
			return nil, ErrIncludeAllNetworks
		}
		return NewMixed(options)
	case "system":
		if options.IncludeAllNetworks {
			return nil, ErrIncludeAllNetworks
		}
		return NewSystem(options)
	default:
		return nil, E.New("unknown stack: ", stack)
	}
}

func HasNextAddress(prefix netip.Prefix, count int) bool {
	checkAddr := prefix.Addr()
	for i := 0; i < count; i++ {
		checkAddr = checkAddr.Next()
	}
	return prefix.Contains(checkAddr)
}

func BroadcastAddr(inet4Address []netip.Prefix) netip.Addr {
	if len(inet4Address) == 0 {
		return netip.Addr{}
	}
	prefix := inet4Address[0]
	var broadcastAddr [4]byte
	binary.BigEndian.PutUint32(broadcastAddr[:], binary.BigEndian.Uint32(prefix.Masked().Addr().AsSlice())|^binary.BigEndian.Uint32(net.CIDRMask(prefix.Bits(), 32)))
	return netip.AddrFrom4(broadcastAddr)
}
