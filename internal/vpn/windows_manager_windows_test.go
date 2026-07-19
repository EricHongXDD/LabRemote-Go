//go:build windows && legacy_ras

package vpn

import (
	"strings"
	"testing"
)

func TestEnsureVPNProfileScriptConfiguresL2TPPreSharedKeyMode(t *testing.T) {
	const expected = "-L2tpPsk $inputValue.psk"
	if occurrences := strings.Count(ensureVPNProfileScript, expected); occurrences != 2 {
		t.Fatalf("创建和更新 L2TP Profile 时都必须配置预共享密钥模式: got %d occurrences", occurrences)
	}
}
