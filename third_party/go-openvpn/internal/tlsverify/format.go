// SPDX-License-Identifier: LGPL-2.1-or-later
//
// format.go: how a certificate is rendered for the verb>=4 log. The shapes
// are OpenSSL's, because the log is read beside `openssl x509` output.

package tlsverify

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"strings"
	"time"
)

// FormatTime renders a validity bound the way OpenSSL prints one.
func FormatTime(t time.Time) string {
	return t.UTC().Format("Jan _2 15:04:05 2006 GMT")
}

// SerialNumber retains a leading zero when it is part of the DER
// serial-number value, matching the value shown by `openssl x509 -serial`.
func SerialNumber(cert *x509.Certificate) string {
	var certificateFields []asn1.RawValue
	if _, err := asn1.Unmarshal(cert.Raw, &certificateFields); err == nil && len(certificateFields) > 0 {
		var tbsFields []asn1.RawValue
		if _, err := asn1.Unmarshal(certificateFields[0].FullBytes, &tbsFields); err != nil {
			return strings.ToUpper(cert.SerialNumber.Text(16))
		}
		index := 0
		if len(tbsFields) > 0 && tbsFields[0].Class == asn1.ClassContextSpecific && tbsFields[0].Tag == 0 {
			index = 1 // Version is optional and precedes the serial number.
		}
		if len(tbsFields) > index && tbsFields[index].Tag == asn1.TagInteger {
			return strings.ToUpper(hex.EncodeToString(tbsFields[index].Bytes))
		}
	}
	return strings.ToUpper(cert.SerialNumber.Text(16))
}

// FormatSANs renders the certificate's subject alternative names, or "<none>"
// for a certificate that carries none.
func FormatSANs(cert *x509.Certificate) string {
	var names []string
	for _, name := range cert.DNSNames {
		names = append(names, "DNS:"+name)
	}
	for _, ip := range cert.IPAddresses {
		names = append(names, "IP Address:"+ip.String())
	}
	if len(names) == 0 {
		return "<none>"
	}
	return strings.Join(names, ", ")
}

// Fingerprint renders the SHA-256 fingerprint of a DER certificate as the
// colon-separated uppercase hex OpenSSL prints.
func Fingerprint(raw []byte) string {
	fingerprint := sha256.Sum256(raw)
	encoded := strings.ToUpper(hex.EncodeToString(fingerprint[:]))
	var fields []string
	for i := 0; i < len(encoded); i += 2 {
		fields = append(fields, encoded[i:i+2])
	}
	return strings.Join(fields, ":")
}
