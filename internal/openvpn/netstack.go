package openvpn

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/buengese/go-openvpn/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type memoryBackend struct{}

type memoryDevice struct {
	tun      tun.Device
	network  *netstack.Net
	address  netip.Addr
	mtu      int
	hasDNS   bool
	outbound chan []byte
	done     chan struct{}
	once     sync.Once
}

// Open 仅创建用户态网络栈；推送的路由和 DNS 不会应用到操作系统。
func (*memoryBackend) Open(ctx context.Context, params device.Params) (device.Device, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if params.Push == nil || params.Push.Ifconfig == nil {
		return nil, fmt.Errorf("OpenVPN 未分配客户端 IPv4 地址")
	}
	address, ok := netip.AddrFromSlice(params.Push.Ifconfig.Local.To4())
	if !ok || address.IsUnspecified() || address.IsMulticast() {
		return nil, fmt.Errorf("OpenVPN 分配的 IPv4 地址无效")
	}
	mtu := params.MTU
	if mtu == 0 {
		mtu = 1500
	}
	if mtu < 576 || mtu > 65535 {
		return nil, fmt.Errorf("OpenVPN MTU 无效")
	}
	var dnsServers []netip.Addr
	if params.DNS != nil {
		for _, ip := range params.DNS.Servers {
			if value, ok := netip.AddrFromSlice(ip.To4()); ok {
				dnsServers = append(dnsServers, value)
			}
		}
	}
	tunDevice, network, err := netstack.CreateNetTUN([]netip.Addr{address}, dnsServers, mtu)
	if err != nil {
		return nil, fmt.Errorf("创建 OpenVPN 用户态网络栈失败")
	}
	d := &memoryDevice{tun: tunDevice, network: network, address: address, mtu: mtu, hasDNS: len(dnsServers) > 0, outbound: make(chan []byte, 256), done: make(chan struct{})}
	go d.readOutbound()
	return d, nil
}

func (d *memoryDevice) readOutbound() {
	buffer := make([]byte, 65535)
	sizes := []int{0}
	for {
		count, err := d.tun.Read([][]byte{buffer}, sizes, 0)
		if err != nil {
			_ = d.Close()
			return
		}
		if count == 0 {
			continue
		}
		packet := append([]byte(nil), buffer[:sizes[0]]...)
		select {
		case d.outbound <- packet:
		case <-d.done:
			return
		}
	}
}

func (d *memoryDevice) ReadPacket(ctx context.Context, buffer []byte) (int, error) {
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-d.done:
		return 0, net.ErrClosed
	case packet := <-d.outbound:
		return copy(buffer, packet), nil
	}
}

func (d *memoryDevice) WritePacket(packet []byte) error {
	select {
	case <-d.done:
		return net.ErrClosed
	default:
	}
	_, err := d.tun.Write([][]byte{packet}, 0)
	return err
}

func (d *memoryDevice) MTU() int     { return d.mtu }
func (d *memoryDevice) Name() string { return "LabRemote OpenVPN 用户态网络栈" }
func (d *memoryDevice) Close() error {
	d.once.Do(func() { close(d.done); _ = d.tun.Close() })
	return nil
}

var _ device.Backend = (*memoryBackend)(nil)
var _ device.Device = (*memoryDevice)(nil)
