package logging

import (
	"strings"
	"testing"
)

func TestRedact(t *testing.T) {
	value := Redact("password=hunter2 authorization:Bearer-abc token=qwerty")
	if strings.Contains(value, "hunter2") || strings.Contains(value, "Bearer-abc") || strings.Contains(value, "qwerty") {
		t.Fatalf("敏感值未被脱敏: %s", value)
	}
	if Redact("Bearer abcdef") != "Bearer [REDACTED]" {
		t.Fatal("Bearer Header 未被整体脱敏")
	}
}
