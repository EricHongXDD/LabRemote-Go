package logging

import (
	"strings"
	"testing"
)

func TestRedact(t *testing.T) {
	value := Redact("password=hunter2 authorization:Bearer-abc token=qwerty passphrase=key-secret private_key_path=C:\\keys\\id_ed25519")
	if strings.Contains(value, "hunter2") || strings.Contains(value, "Bearer-abc") || strings.Contains(value, "qwerty") || strings.Contains(value, "key-secret") || strings.Contains(value, "id_ed25519") {
		t.Fatalf("敏感值未被脱敏: %s", value)
	}
	if Redact("Bearer abcdef") != "Bearer [REDACTED]" {
		t.Fatal("Bearer Header 未被整体脱敏")
	}
}
