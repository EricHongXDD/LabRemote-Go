// SPDX-License-Identifier: LGPL-2.1-or-later

package crypto

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestNullCipherHMACAndTamper(t *testing.T) {
	cipher, err := NewNullCipher(DigestSHA1, bytes.Repeat([]byte{1}, 20))
	if err != nil {
		t.Fatal(err)
	}
	plain := append([]byte{0, 0, 0, 1}, []byte("packet")...)
	wire := cipher.Seal(1, plain, nil)
	if got := hex.EncodeToString(wire[:20]); got != "8d9b8b9b84d12698028493525e2efbc709879a86" {
		t.Fatalf("认证向量不匹配: %s", got)
	}
	decoded, err := cipher.Open(1, wire, nil)
	if err != nil || !bytes.Equal(decoded, plain) {
		t.Fatal("认证载荷往返失败")
	}
	wire[len(wire)-1] ^= 1
	if _, err := cipher.Open(1, wire, nil); err == nil {
		t.Fatal("篡改的认证数据未拒绝")
	}
}
