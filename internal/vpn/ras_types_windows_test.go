//go:build windows && amd64 && legacy_ras

package vpn

import (
	"testing"
	"unsafe"
)

func TestRASStructureSizesAMD64(t *testing.T) {
	if size := unsafe.Sizeof(rasDialParams{}); size != 2120 {
		t.Fatalf("RASDIALPARAMSW 结构大小异常: got %d, want 2120", size)
	}
	if size := unsafe.Sizeof(rasCredentials{}); size != 1068 {
		t.Fatalf("RASCREDENTIALSW 结构大小异常: got %d, want 1068", size)
	}
	if size := unsafe.Sizeof(rasConnection{}); size != 1392 {
		t.Fatalf("RASCONNW 结构大小异常: got %d, want 1392", size)
	}
	if size := unsafe.Sizeof(rasConnectStatus{}); size != 608 {
		t.Fatalf("RASCONNSTATUSW 结构大小异常: got %d, want 608", size)
	}
}
