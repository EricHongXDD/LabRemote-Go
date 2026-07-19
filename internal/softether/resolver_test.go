package softether

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestLookupIPv4HandlesCNAMEAnswer(t *testing.T) {
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	serverResult := make(chan error, 1)
	go func() {
		buffer := make([]byte, 2048)
		read, remote, readErr := server.ReadFrom(buffer)
		if readErr != nil {
			serverResult <- readErr
			return
		}
		var parser dnsmessage.Parser
		header, parseErr := parser.Start(buffer[:read])
		if parseErr != nil {
			serverResult <- parseErr
			return
		}
		question, parseErr := parser.Question()
		if parseErr != nil {
			serverResult <- parseErr
			return
		}
		alias := dnsmessage.MustNewName("alias.labremote.test.")
		builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{
			ID: header.ID, Response: true, RecursionDesired: header.RecursionDesired, RecursionAvailable: true,
		})
		builder.EnableCompression()
		if buildErr := builder.StartQuestions(); buildErr != nil {
			serverResult <- buildErr
			return
		}
		if buildErr := builder.Question(question); buildErr != nil {
			serverResult <- buildErr
			return
		}
		if buildErr := builder.StartAnswers(); buildErr != nil {
			serverResult <- buildErr
			return
		}
		if buildErr := builder.CNAMEResource(
			dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: 60},
			dnsmessage.CNAMEResource{CNAME: alias},
		); buildErr != nil {
			serverResult <- buildErr
			return
		}
		if buildErr := builder.AResource(
			dnsmessage.ResourceHeader{Name: alias, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
			dnsmessage.AResource{A: [4]byte{203, 0, 113, 7}},
		); buildErr != nil {
			serverResult <- buildErr
			return
		}
		response, buildErr := builder.Finish()
		if buildErr != nil {
			serverResult <- buildErr
			return
		}
		_, writeErr := server.WriteTo(response, remote)
		serverResult <- writeErr
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	addresses, err := lookupIPv4(ctx, "service.labremote.test", func(dialContext context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(dialContext, "udp4", server.LocalAddr().String())
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(addresses) != 1 || addresses[0] != netip.MustParseAddr("203.0.113.7") {
		t.Fatalf("解析结果不符合预期: %v", addresses)
	}
	if serverErr := <-serverResult; serverErr != nil {
		t.Fatal(serverErr)
	}
}

func TestTunnelDNSServersRequiresGatewayForPublicFallback(t *testing.T) {
	servers, err := tunnelDNSServers(Lease{DNS: net.IPv4(192, 168, 10, 53)})
	if err != nil || len(servers) != 1 || servers[0] != netip.MustParseAddr("192.168.10.53") {
		t.Fatalf("应优先使用 DHCP DNS: servers=%v err=%v", servers, err)
	}
	if _, err := tunnelDNSServers(Lease{}); err == nil {
		t.Fatal("DHCP 同时缺少 DNS 和网关时应返回明确错误")
	}
	servers, err = tunnelDNSServers(Lease{Gateway: net.IPv4(192, 168, 10, 1)})
	if err != nil || len(servers) != 2 {
		t.Fatalf("存在网关时应提供隧道内备用 DNS: servers=%v err=%v", servers, err)
	}
}
