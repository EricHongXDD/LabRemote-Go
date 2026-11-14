package saml_test

import (
	"testing"

	"github.com/buengese/go-openvpn/auth/saml"
)

// FuzzParseCRV1 feeds random strings to ParseCRV1 to verify it never panics.
func FuzzParseCRV1(f *testing.F) {
	// Seed: realistic CRV1 message.
	f.Add("AUTH_FAILED,CRV1:R:instance-1/abc:b'XXXX':https://portal.sso.us-east-1.amazonaws.com/saml")
	// Seed: with remote IP.
	f.Add("AUTH_FAILED,CRV1:R,52.1.2.3:state-xyz:b'AA==':https://example.com/sso?foo=bar")
	// Seed: not a CRV1 message.
	f.Add("AUTH_FAILED,Invalid username or password")
	// Seed: minimal valid structure.
	f.Add("AUTH_FAILED,CRV1:R:s:u:https://x")
	// Seed: missing colons.
	f.Add("AUTH_FAILED,CRV1:R")
	// Seed: empty string.
	f.Add("")

	f.Fuzz(func(t *testing.T, msg string) {
		_, _ = saml.ParseCRV1(msg)
	})
}
