package saml

import (
	"encoding/base64"
	"testing"
	"time"
)

// TestTokenExpiry covers the assertion timestamps TokenExpiry reads out of a
// base64-wrapped SAML response: the earliest NotOnOrAfter wins wherever several
// appear, and anything it cannot read yields the zero time rather than an
// error, so a missing expiry is not mistaken for an immediate one.
func TestTokenExpiry(t *testing.T) {
	tests := []struct {
		name string
		// raw is the SAML document; it is base64-encoded before the call.
		raw string
		// rawIsToken passes raw through untouched, for the malformed case.
		rawIsToken bool
		want       time.Time
	}{
		{
			name: "subject confirmation data",
			raw: `<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    <saml:Conditions NotBefore="2024-01-01T10:00:00Z" NotOnOrAfter="2024-01-01T10:05:00Z"/>
    <saml:AuthnStatement/>
  </saml:Assertion>
</samlp:Response>`,
			want: time.Date(2024, 1, 1, 10, 5, 0, 0, time.UTC),
		},
		{
			name: "earliest of several wins",
			raw: `<Assertion>
  <Conditions NotOnOrAfter="2024-06-01T12:00:00Z"/>
  <SubjectConfirmationData NotOnOrAfter="2024-06-01T11:30:00Z"/>
</Assertion>`,
			want: time.Date(2024, 6, 1, 11, 30, 0, 0, time.UTC),
		},
		{
			// Some IdPs include milliseconds; the fractional second must not
			// make the timestamp unparseable.
			name: "millisecond precision",
			raw:  `<Conditions NotOnOrAfter="2024-03-15T08:45:30.500Z"/>`,
			want: time.Date(2024, 3, 15, 8, 45, 30, 500_000_000, time.UTC),
		},
		{
			name: "no expiry at all",
			raw:  `<Assertion><AuthnStatement/></Assertion>`,
			want: time.Time{},
		},
		{
			name:       "not base64",
			raw:        "not-valid-base64!!!",
			rawIsToken: true,
			want:       time.Time{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := tt.raw
			if !tt.rawIsToken {
				token = base64.StdEncoding.EncodeToString([]byte(tt.raw))
			}
			got := TokenExpiry(token)
			if !got.Equal(tt.want) {
				t.Errorf("TokenExpiry = %v, want %v", got, tt.want)
			}
		})
	}
}
