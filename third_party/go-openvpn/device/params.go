// SPDX-License-Identifier: LGPL-2.1-or-later

package device

import (
	"net"

	"github.com/buengese/go-openvpn/dns"
	"github.com/buengese/go-openvpn/routing"
)

// Params is everything a backend needs to bring the tunnel up: the parsed
// PUSH_REPLY plus the two things the core knows and it does not — the negotiated
// MTU and the address the transport connected to. A backend reads Params and
// does not otherwise consult the profile.
type Params struct {
	// Push is the parsed PUSH_REPLY: addressing, routes, redirect-gateway.
	// A backend that needs an address takes it from Push.Ifconfig or
	// Push.Ifconfig6 and must tolerate either being nil.
	Push *routing.PushOptions

	// DNS is the pushed and profile DNS, already merged. Nil when the
	// server pushed none and the profile named none. Backends whose host
	// owns DNS — fd, netstack — record it and apply nothing.
	DNS *dns.Config

	// MTU is the negotiated tunnel MTU in bytes.
	MTU int

	// ServerIP is the endpoint the transport connected to. The kernel
	// backend needs it for the bypass route that keeps the tunnel's own
	// socket off the tunnel when redirect-gateway is active. A backend
	// installing no host routes has no use for it.
	ServerIP net.IP
}
