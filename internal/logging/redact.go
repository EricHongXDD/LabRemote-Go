package logging

import (
	"regexp"
	"strings"
)

var sensitiveAssignment = regexp.MustCompile(`(?i)(password|passwd|psk|pre[_-]?shared[_-]?key|authorization|bearer|token|secret)(\s*[:=]\s*)([^\s,;]+)`)

func Redact(value string) string {
	value = sensitiveAssignment.ReplaceAllString(value, "$1$2[REDACTED]")
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(value)), "bearer ") {
		return "Bearer [REDACTED]"
	}
	return value
}
