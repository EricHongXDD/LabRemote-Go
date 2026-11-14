// SPDX-License-Identifier: LGPL-2.1-or-later
//
// advertise.go: what the client advertises about itself to the server.

package vpn

import (
	"github.com/buengese/go-openvpn/internal/datachannel"
	"github.com/buengese/go-openvpn/internal/keymethod2"
	"github.com/buengese/go-openvpn/profile"
)

// DataV2Advertisement selects whether this client's IV_PROTO advertisement
// claims IV_PROTO_DATA_V2.
type DataV2Advertisement int

const (
	// AdvertiseDataV2 claims the bit. It is the zero value and the default:
	// P_DATA_V2 is the format this client prefers, and a server that hears
	// the bit assigns a peer-id and speaks it.
	AdvertiseDataV2 DataV2Advertisement = iota

	// WithholdDataV2 advertises IV_PROTO=0 — no protocol extensions at
	// all — so the server assigns no peer-id and speaks P_DATA_V1. Clearing
	// the DATA_V2 bit alone does not reach P_DATA_V1:
	//
	//	IV_PROTO   pushed          data opcode
	//	      30   peer-id 0       P_DATA_V2
	//	      28   peer-id 0       P_DATA_V2   (every bit but DATA_V2)
	//	       4   peer-id 0       P_DATA_V2   (no DATA_V2 bit at all)
	//	       0   nothing         P_DATA_V1
	//
	// OpenVPN 2.4 and 2.5 decide in push.c:prepare_push_reply on a numeric
	// comparison rather than a bit test —
	//
	//	int r = sscanf(optstr, "IV_PROTO=%d", &proto);
	//	if ((r == 1) && (proto >= 2)) { push "peer-id"; use_peer_id = true; }
	//
	// — so any bit above the lowest keeps the peer-id coming, while 2.6 uses
	// the bit test (multi.c:multi_client_connect_late_setup via
	// extract_iv_proto) and 0 satisfies both. The three remaining bits go with
	// it, and against a 2.4 peer they cost nothing: the keying-material
	// exporter and auth-pending are 2.6 features.
	//
	// Withholding a bit can only make a server offer less than the client
	// implements, so it does not breach the rule the advertisement is built
	// on, and both wire formats are implemented
	// (internal/datachannel.WireFormat). It is not a fallback and not a
	// preference: a connection that withholds it still takes its format from
	// what the server pushes. The vehicle is the matrix isolate
	// v24-cbc256-sha256-plain-udp-datav1, there being no server-side switch
	// for P_DATA_V1 on any pinned version.
	WithholdDataV2
)

// peerInfo is the IV_* capability advertisement a normal connection sends. It
// is rendered once, so the block every reader of this variable sees is the one
// that goes on the wire. What the bits mean, and the rule that IV_PROTO may
// advertise only implemented features, are on keymethod2.PeerInfo.
var peerInfo = keymethod2.PeerInfo(keymethod2.IVProtoImplemented)

// ivProtoFor is the IV_PROTO value one advertisement sends, which is the whole
// of what DataV2Advertisement means on the wire. The exported type cannot
// cross into internal/keymethod2, so the mapping happens here, once.
func ivProtoFor(adv DataV2Advertisement) uint32 {
	if adv == WithholdDataV2 {
		return keymethod2.IVProtoNoExtensions
	}
	return keymethod2.IVProtoImplemented
}

// peerInfoFor is the peer-info block to send under a given advertisement. The
// default returns peerInfo itself, so the block a normal connection sends is
// the same object every reader of that variable sees.
//
// It derives the value from ivProtoFor rather than testing adv a second time:
// the report reads this block while keymethod2.SendAuth is handed the IV_PROTO
// value, and two independent decisions could disagree — a session sending
// IV_PROTO=0 on the wire while reporting 30.
func peerInfoFor(adv DataV2Advertisement) string {
	if p := ivProtoFor(adv); p != keymethod2.IVProtoImplemented {
		return keymethod2.PeerInfo(p)
	}
	return peerInfo
}

// tunnelParams renders the negotiated data-channel parameters as the plain
// values the options string is built from. keymethod2 takes values rather than
// datachannel.Params so that the wire format does not depend on the cipher
// table; this is the one place the two meet, and the [null-digest] rule lives
// on the keymethod2 side.
func tunnelParams(proto profile.Proto, tunMTU int, params datachannel.Params) keymethod2.TunnelParams {
	tp := keymethod2.TunnelParams{
		Proto:       proto,
		TunMTU:      tunMTU,
		CipherName:  params.Spec.Name,
		KeySizeBits: params.Spec.KeyLen * 8,
	}
	if params.Spec.UsesDigest() {
		tp.AuthName = params.Digest.String()
	}
	return tp
}
