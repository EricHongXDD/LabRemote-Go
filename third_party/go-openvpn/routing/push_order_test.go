// Directive order independence for ParsePushReply.
//
// A PUSH_REPLY is a set of directives, not a program. The reference reads the
// whole option list before it interprets any of it: openvpn-2.6.22
// src/openvpn/options.c add_option() stores the two "ifconfig" arguments as
// strings and "topology" as an integer, and src/openvpn/tun.c init_tun()
// decides there what the second ifconfig argument means. The assertion here is
// that property, not a golden struct: the same directives in any order parse
// to the same options.
package routing

import (
	"fmt"
	"math/rand/v2"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// pushOrderReplies are the PUSH_REPLY messages whose directives get reordered.
// The full reply carries one of every directive whose meaning could depend on
// another, plus two that are there to be ignored. The second drops
// route-gateway, because an explicit route-gateway is itself what hides a
// misread ifconfig: it overwrites the gateway whatever the ifconfig arm put
// there.
var pushOrderReplies = []struct {
	name       string
	directives []string
}{
	{"full_subnet_reply", []string{
		"topology subnet",
		"ifconfig 172.16.77.4 255.255.255.224",
		"route-gateway 172.16.77.1",
		"ifconfig-ipv6 fd00:77::4/64 fd00:77::1",
		"route 10.130.0.0 255.255.0.0",
		"route 192.168.30.0 255.255.255.0 net_gateway",
		"route-ipv6 2000::/3",
		"route-ipv6 fd00:99::/48 fd00:77::1",
		"redirect-gateway def1 bypass-dhcp",
		"cipher AES-256-GCM",
		"auth SHA512",
		"compress stub-v2",
		"ping 10",
		"ping-restart 60",
		"tun-mtu 1400",
		"mssfix 1300",
		"protocol-flags tls-ekm cc-exit",
		"inactive 600 4096",
		"auth-token SESS_ID_abcdef",
		"dhcp-option DNS 10.130.0.2",
		"peer-id 7",
	}},
	{"subnet_without_route_gateway", []string{
		"topology subnet",
		"ifconfig 10.8.0.6 255.255.255.0",
		"route 10.8.0.0 255.255.0.0",
		"redirect-gateway def1",
		"ping 10",
	}},
}

// addressingDirectives are the keywords whose interpretation depends on one
// another, and so the ones worth permuting exhaustively.
var addressingDirectives = map[string]bool{
	"topology":      true,
	"ifconfig":      true,
	"route-gateway": true,
	"ifconfig-ipv6": true,
}

// joinPush renders directives as the control message a server would send,
// trailing NUL included.
func joinPush(directives []string) string {
	return "PUSH_REPLY," + strings.Join(directives, ",") + "\x00"
}

// keyword returns a directive's first word.
func keyword(directive string) string {
	return strings.ToLower(strings.Fields(directive)[0])
}

// normalisePush returns opts with its route lists sorted, so that two parses
// can be compared on everything except the one thing directive order is
// entitled to decide: routes accumulate in arrival order, because that is the
// order the reference installs them in (openvpn-2.6.22 src/openvpn/route.c
// add_routes() walks the list as it was built).
func normalisePush(opts *PushOptions) *PushOptions {
	c := *opts
	c.Routes = slices.Clone(opts.Routes)
	slices.SortFunc(c.Routes, func(a, b Route) int {
		return strings.Compare(fmt.Sprint(a), fmt.Sprint(b))
	})
	c.Routes6 = slices.Clone(opts.Routes6)
	slices.SortFunc(c.Routes6, func(a, b Route6) int {
		return strings.Compare(fmt.Sprint(a), fmt.Sprint(b))
	})
	return &c
}

// pushFieldDiff names the PushOptions fields on which got and want disagree,
// so that a failure says which option the reordering moved rather than
// printing two twenty-field structs side by side.
func pushFieldDiff(got, want *PushOptions) []string {
	gv, wv := reflect.ValueOf(*got), reflect.ValueOf(*want)
	var out []string
	for i := range gv.NumField() {
		g, w := gv.Field(i), wv.Field(i)
		if reflect.DeepEqual(g.Interface(), w.Interface()) {
			continue
		}
		out = append(out, fmt.Sprintf("%s: got %v, want %v",
			gv.Type().Field(i).Name, deref(g), deref(w)))
	}
	return out
}

// deref renders a possibly-pointer field by its value, so that a differing
// Ifconfig prints its addresses instead of a heap address.
func deref(v reflect.Value) any {
	if v.Kind() == reflect.Pointer && !v.IsNil() {
		return v.Elem().Interface()
	}
	return v.Interface()
}

// pushOrderCase is one ordering of a reply's directives.
type pushOrderCase struct {
	name  string
	order []string
}

// pushOrderCases builds the orderings to try for one reply: the adversarial
// ones by hand, every permutation of the addressing directives among their own
// positions, and a fixed-seed sample of whole-message shuffles.
func pushOrderCases(base []string) []pushOrderCase {
	// moved lifts the directive with the given keyword out of the list and
	// puts it back at to, which may be negative to count from the end.
	moved := func(name, kw string, to int) pushOrderCase {
		o := slices.Clone(base)
		from := slices.IndexFunc(o, func(d string) bool { return keyword(d) == kw })
		d := o[from]
		o = slices.Delete(o, from, from+1)
		if to < 0 {
			to += len(o) + 1
		}
		return pushOrderCase{name, slices.Insert(o, to, d)}
	}

	reversed := slices.Clone(base)
	slices.Reverse(reversed)
	ascending := slices.Sorted(slices.Values(base))
	descending := slices.Clone(ascending)
	slices.Reverse(descending)

	cases := []pushOrderCase{
		{"as_sent", slices.Clone(base)},
		{"reversed", reversed},
		{"alphabetical", ascending},
		{"reverse_alphabetical", descending},
		// topology one place later than sent.
		moved("topology_after_ifconfig", "topology", 1),
		moved("topology_last", "topology", -1),
		moved("ifconfig_first", "ifconfig", 0),
	}

	// Every order of the addressing directives, permuted among the positions
	// they already occupy so that the rest of the reply stays put.
	var at []int
	for i, d := range base {
		if addressingDirectives[keyword(d)] {
			at = append(at, i)
		}
	}
	perm := make([]int, len(at))
	for i := range perm {
		perm[i] = i
	}
	for n := 0; ; n++ {
		o := slices.Clone(base)
		for i, p := range perm {
			o[at[i]] = base[at[p]]
		}
		cases = append(cases, pushOrderCase{fmt.Sprintf("addressing_perm_%02d", n), o})
		if !nextPermutation(perm) {
			break
		}
	}

	// Whole-message shuffles. The seed is fixed so that a failure reproduces.
	rng := rand.New(rand.NewPCG(1194, 1195))
	for n := range 64 {
		o := slices.Clone(base)
		rng.Shuffle(len(o), func(i, j int) { o[i], o[j] = o[j], o[i] })
		cases = append(cases, pushOrderCase{fmt.Sprintf("shuffle_%02d", n), o})
	}

	return cases
}

// nextPermutation advances p to the next permutation in lexicographic order
// and reports whether there was one.
func nextPermutation(p []int) bool {
	i := len(p) - 2
	for i >= 0 && p[i] >= p[i+1] {
		i--
	}
	if i < 0 {
		return false
	}
	j := len(p) - 1
	for p[j] <= p[i] {
		j--
	}
	p[i], p[j] = p[j], p[i]
	slices.Reverse(p[i+1:])
	return true
}

// TestParsePushReplyDirectiveOrderIsIrrelevant asserts that reordering the
// directives of a PUSH_REPLY does not change what ParsePushReply makes of it.
// The server decides the order and the protocol does not constrain it: stock
// OpenVPN emits pushed options in the order the server configuration lists them
// (openvpn-2.6.22 src/openvpn/push.c send_push_reply).
func TestParsePushReplyDirectiveOrderIsIrrelevant(t *testing.T) {
	for _, reply := range pushOrderReplies {
		t.Run(reply.name, func(t *testing.T) {
			want, err := ParsePushReply(joinPush(reply.directives))
			if err != nil {
				t.Fatalf("ParsePushReply of the order as listed: %v", err)
			}
			want = normalisePush(want)

			for _, tc := range pushOrderCases(reply.directives) {
				t.Run(tc.name, func(t *testing.T) {
					got, err := ParsePushReply(joinPush(tc.order))
					if err != nil {
						t.Fatalf("ParsePushReply: %v\norder: %s",
							err, strings.Join(tc.order, ","))
					}
					diff := pushFieldDiff(normalisePush(got), want)
					if len(diff) == 0 {
						return
					}
					t.Errorf("directive order changed the parse:\n  %s\norder: %s",
						strings.Join(diff, "\n  "), strings.Join(tc.order, ","))
				})
			}
		})
	}
}
