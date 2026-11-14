// SPDX-License-Identifier: LGPL-2.1-or-later

// Package device is the tunnel device seam.
//
// The client core moves raw IP packets and has no business knowing whether they
// reach a kernel interface, a descriptor handed over by Android's VpnService,
// or a userspace network stack in the same process. Device is that boundary,
// and Backend produces one from the parameters a server pushed.
//
// Everything privileged — addressing, routes, DNS — lives behind a backend and
// nowhere else, and a backend that installs host state owns unwinding it in
// Device.Close.
//
// This package is a leaf: it depends on routing and dns for the shape of the
// pushed options and on nothing else of ours. It must never import the root vpn
// package, which imports this one.
package device

import "context"

// Device is one end of a tunnel: raw IP packets, no framing. Read is outbound
// (host to wire), Write is inbound (wire to host), and any framing a platform
// requires — the four-byte address-family header a Darwin utun prepends, for
// instance — is the backend's business and must not reach the caller.
//
// # Concurrency
//
// ReadPacket is called from exactly one goroutine and WritePacket from exactly
// one other, concurrently, for the life of the tunnel: an implementation must
// make those two paths safe against each other, but needs no protection against
// concurrent calls to either one.
//
// Close may be called from a third goroutine at any time, including while a
// ReadPacket is blocked, and must not deadlock waiting for that call to return.
// MTU and Name are constant after Open returns.
type Device interface {
	// ReadPacket blocks until an outbound packet is available, fills buf,
	// and returns its length — or returns ctx.Err() when ctx ends.
	//
	// A packet longer than buf is truncated rather than split; buf should
	// be at least MTU bytes.
	ReadPacket(ctx context.Context, buf []byte) (int, error)

	// WritePacket delivers one inbound IP packet. It must not retain pkt:
	// the caller reuses the buffer as soon as WritePacket returns.
	WritePacket(pkt []byte) error

	// MTU is the negotiated tunnel MTU in bytes.
	MTU() int

	// Name identifies the device in logs and reports: an interface name for
	// the kernel and fd backends, a synthetic name for netstack.
	Name() string

	// Close releases the device and everything the backend installed
	// alongside it — addresses, routes, DNS. It is idempotent, and it
	// unblocks any ReadPacket in flight.
	Close() error
}

// Backend turns negotiated tunnel parameters into a Device. One Backend serves
// one tunnel and one Device at a time.
//
// A reconnect opens a second Device from the same Backend, once the first has
// been closed: addresses, routes and MTU come from the PUSH_REPLY, and the
// session that comes back need not have been pushed what the last one was. Open
// is called once per connection attempt that gets that far, never concurrently,
// and never again for a Device that is still open.
//
// Open either returns a usable Device or returns an error having left the host
// exactly as it found it, unwinding anything it installed on the way.
type Backend interface {
	// Open brings the tunnel device up from the parameters in p. The
	// context bounds the setup work only; it does not bound the lifetime of
	// the returned Device, which ends at Close.
	Open(ctx context.Context, p Params) (Device, error)
}

// Kind names a backend in the session report. The values are recorded in
// aggregated measurement data and must stay stable.
type Kind string

const (
	// KindKernel is the privileged backend: a kernel TUN interface with
	// netlink routes and host DNS. Requires CAP_NET_ADMIN.
	KindKernel Kind = "kernel"
	// KindFD is the mobile backend: a descriptor supplied by the host,
	// which owns addressing, routes and DNS itself.
	KindFD Kind = "fd"
	// KindNetstack is the userspace backend: a network stack in this
	// process, touching no host state and needing no privilege.
	KindNetstack Kind = "netstack"
)

// String returns the kind as it appears in a session report.
func (k Kind) String() string { return string(k) }
