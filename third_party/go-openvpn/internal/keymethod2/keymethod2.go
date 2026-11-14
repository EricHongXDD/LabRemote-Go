// SPDX-License-Identifier: LGPL-2.1-or-later

// Package keymethod2 implements the OpenVPN key-method-2 auth exchange in both
// framings it is spoken in: the stock uint16_be one, and the AWS Client VPN
// patched uint32 one that exists because SAML assertions outgrow a uint16
// length field.
//
// It is bytes and nothing else — what the client advertises about itself, what
// it sends, and what it reads back — so every claim it makes can be checked
// against a known answer rather than against a live server. The tunnel options
// string and the peer-info block are here because they are part of this
// packet's payload, and a deployment told the wrong cipher rejects the
// credentials that came with it.
package keymethod2

import (
	"fmt"
	"strings"

	"github.com/buengese/go-openvpn/internal/crypto"
	"github.com/buengese/go-openvpn/profile"
)

// The IV_PROTO bits this client implements, and their sum.
//
// They are named rather than added up by hand because the sum is asked for
// twice — once whole, once without DATA_V2 — and a literal 30 in a string is
// not something a reader can check against the list of bits.
//
// Reference: OpenVPN 2 src/openvpn/ssl.h IV_PROTO_* and
// doc/openvpn-protocol-extensions.txt.
const (
	// IVProtoDataV2 makes a 2.6 server assign a peer-id and speak
	// P_DATA_V2. 2.4 and 2.5 do the same for any IV_PROTO value of 2 or
	// more, whatever this bit says — see the root package's WithholdDataV2,
	// which is why that lever sends 0 rather than clearing a bit.
	IVProtoDataV2 = 1 << 1
	// IVProtoRequestPush says the client will send PUSH_REQUEST itself.
	IVProtoRequestPush = 1 << 2
	// IVProtoTLSKeyExport offers the RFC 5705 EKM data-key derivation.
	IVProtoTLSKeyExport = 1 << 3
	// IVProtoAuthPending is upstream's IV_PROTO_AUTH_PENDING_KW, "Supports
	// signaling keywords with AUTH_PENDING, e.g. timeout=xy" (ssl.h:89-90).
	// All the bit decides is the *form* of a server's AUTH_PENDING message:
	// push.c:457-470 appends ",timeout N" when it is claimed and sends a bare
	// AUTH_PENDING when it is not. It is not the AUTH_FAILED,CRV1 challenge,
	// which push.c:119 handles on a different message and gates on no IV_PROTO
	// bit at all, and it is not SAML. The mid-session AUTH_PENDING loop
	// itself is only partially implemented: the bit is advertised and the
	// message is recognised, and nothing resumes the exchange it asks for.
	IVProtoAuthPending = 1 << 4

	// IVProtoImplemented is every bit above — 30 — and is what this client
	// advertises unless a caller withholds DATA_V2 for the P_DATA_V1 matrix
	// isolate. Nothing may be added to it that is not implemented; see
	// PeerInfo.
	IVProtoImplemented = IVProtoDataV2 | IVProtoRequestPush | IVProtoTLSKeyExport | IVProtoAuthPending

	// IVProtoNoExtensions claims none of them, which is what the root
	// package's WithholdDataV2 sends and the only value that makes every
	// pinned server version decline to assign a peer-id.
	IVProtoNoExtensions = 0
)

// PeerInfo renders the IV_* capability advertisement sent in the auth packet,
// for one IV_PROTO value. It is the only place the block's shape exists.
//
// IV_PROTO must advertise ONLY features this client implements: a server
// enables a negotiated feature when the client claims it, and then speaks it on
// the wire. CC_EXIT_NOTIFY (1<<7), AUTH_FAIL_TEMP (1<<8), DYN_TLS_CRYPT (1<<9),
// DATA_EPOCH (1<<10), DNS_OPTION_V2 (1<<11) and PUSH_UPDATE (1<<12) are
// therefore withheld. DATA_EPOCH in particular selects a data-channel packet
// format and key schedule this client cannot decode, and control-channel TLS
// and SAML would still succeed while every data packet failed.
//
// IVProtoImplemented advertises the four bits named above — 30 — which keeps
// EKM (correct key derivation) while making the server fall back to the
// classic AEAD data channel. The AWS CRV1 challenge this client answers at
// connect rides on none of these bits.
//
// IV_CIPHERS is generated from the cipher table in internal/crypto rather than
// written out here: a server speaks whatever cipher it selects from that list,
// so advertising one we cannot build is a promise broken at the first data
// packet. TestIVCiphersIsHonest asserts the two still agree.
func PeerInfo(ivProto uint32) string {
	return fmt.Sprintf("IV_VER=3.11.6\nIV_PLAT=linux\nIV_NCP=2\nIV_TCPNL=1\nIV_PROTO=%d\nIV_MTU=1600\n"+
		"IV_CIPHERS=%s\n", ivProto, strings.Join(crypto.CipherNames(), ":"))
}

// TunnelParams is what the options string advertises about the data channel.
// It is plain values rather than the negotiated datachannel.Params it derives
// from, so this package depends on the wire format alone and not on the cipher
// table the caller resolved against.
type TunnelParams struct {
	// Proto is the transport actually dialled, which is not necessarily the
	// profile's: link-mtu and the proto field both follow it.
	Proto profile.Proto
	// TunMTU is the configured TUN MTU; zero means OpenVPN's 1500 default.
	TunMTU int
	// CipherName is the negotiated cipher's OpenVPN name.
	CipherName string
	// AuthName is the negotiated CBC digest's name. Empty for an AEAD
	// cipher, which reports its digest as [null-digest] because it
	// authenticates its own output.
	AuthName string
	// KeySizeBits is the cipher's key length in bits.
	KeySizeBits int
}

// TunnelOptions returns the options string sent in the key-method-2 auth
// packet. The string is dynamic because proto and link-mtu differ between TCP
// and UDP connections — advertising the wrong proto causes AUTH_FAILED.
//
// Values match what openvpn3-core 3.11.6 sends for each transport at a
// 1500-byte TUN MTU. link-mtu tracks a configured TUN MTU by retaining the
// same transport overhead: 21 bytes for UDP and 43 bytes for TCP.
//
// The cipher, auth and keysize fields describe what this connection will
// actually use, because the server checks the string against its own
// configuration: a CBC deployment told AES-256-GCM is a plausible cause of a
// rejection that looks like a credential problem. An AEAD cipher reports its
// digest as [null-digest], because it authenticates its own output; a CBC
// cipher names the real digest. keysize is the cipher's key length in bits.
func TunnelOptions(p TunnelParams) string {
	tunMTU := p.TunMTU
	if tunMTU == 0 {
		tunMTU = 1500
	}
	protoStr := "UDPv4"
	linkMTU := tunMTU + 21
	if p.Proto == profile.ProtoTCP {
		protoStr = "TCPv4_CLIENT"
		linkMTU = tunMTU + 43
	}
	auth := "[null-digest]"
	if p.AuthName != "" {
		auth = p.AuthName
	}
	return fmt.Sprintf(
		"V4,dev-type tun,link-mtu %d,tun-mtu %d,proto %s,cipher %s,auth %s,keysize %d,key-method 2,tls-client",
		linkMTU, tunMTU, protoStr, p.CipherName, auth, p.KeySizeBits,
	)
}
