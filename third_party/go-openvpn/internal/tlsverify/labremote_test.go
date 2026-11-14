// SPDX-License-Identifier: LGPL-2.1-or-later

package tlsverify

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLabRemoteNeverWritesTLSSecrets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.log")
	profile := keylogProfile(t, path, testCAPEM(t))
	for range 3 {
		config, _, err := BuildConfig(profile)
		if err != nil {
			t.Fatal(err)
		}
		if config.KeyLogWriter != nil {
			t.Fatal("不应允许环境变量启用 TLS 密钥文件")
		}
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("不应创建 TLS 密钥文件")
	}
}
