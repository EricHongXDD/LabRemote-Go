package softether

import (
	"encoding/base64"
	"testing"
)

func TestSHA0CompatibilityVector(t *testing.T) {
	value := sha0([]byte("password1USERNAME1"))
	if actual := base64.StdEncoding.EncodeToString(value[:]); actual != "yQutDhGqXao5a5j3FHs3jI7qazw=" {
		t.Fatalf("SHA-0 兼容向量不匹配: %s", actual)
	}
}

func TestPackRoundTrip(t *testing.T) {
	value := &pack{}
	value.addString("method", "enum_hub")
	value.addInt("client_ver", 1000)
	value.addBool("qos", false)
	value.addData("unique_id", []byte{1, 2, 3, 4})
	value.addStrings("HubName", []string{"one", "two"})
	data, err := value.marshal()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := unmarshalPack(data)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.getString("method") != "enum_hub" || decoded.getInt("client_ver") != 1000 || decoded.getBool("qos") {
		t.Fatal("PACK 标量往返失败")
	}
	if decoded.stringCount("HubName") != 2 || decoded.getStringAt("HubName", 1) != "two" {
		t.Fatal("PACK 数组往返失败")
	}
}

func TestPackRejectsCaseInsensitiveDuplicate(t *testing.T) {
	value := &pack{}
	value.addData("unique_id", []byte{1})
	value.addData("UNIQUE_ID", []byte{2})
	if len(value.elements) != 1 {
		t.Fatalf("应忽略大小写重复元素，实际为 %d", len(value.elements))
	}
}
