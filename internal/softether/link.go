package softether

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type Lease struct {
	Address   net.IP
	Mask      net.IPMask
	Gateway   net.IP
	DNS       net.IP
	LeaseTime time.Duration
}

type Link struct {
	session  *Session
	device   tun.Device
	network  *netstack.Net
	lease    Lease
	mac      [6]byte
	arpMu    sync.RWMutex
	arpTable map[[4]byte][6]byte
	done     chan struct{}
	stopOnce sync.Once
	errMu    sync.RWMutex
	err      error
}

func NewLink(ctx context.Context, session *Session) (*Link, error) {
	mac, err := randomMAC()
	if err != nil {
		return nil, err
	}
	lease, err := acquireDHCP(ctx, session, mac)
	if err != nil {
		return nil, err
	}
	localAddress, ok := netip.AddrFromSlice(lease.Address.To4())
	if !ok {
		return nil, errors.New("DHCP 返回了无效 IPv4 地址")
	}
	dnsServers := make([]netip.Addr, 0, 1)
	if dns, ok := netip.AddrFromSlice(lease.DNS.To4()); ok {
		dnsServers = append(dnsServers, dns)
	}
	device, network, err := netstack.CreateNetTUN([]netip.Addr{localAddress}, dnsServers, 1500)
	if err != nil {
		return nil, fmt.Errorf("创建用户态 TCP/IP 栈失败: %w", err)
	}
	link := &Link{
		session: session, device: device, network: network, lease: lease, mac: mac,
		arpTable: make(map[[4]byte][6]byte), done: make(chan struct{}),
	}
	go link.inboundLoop()
	go link.outboundLoop()
	go func() {
		<-session.Done()
		link.stop(session.Err())
	}()
	return link, nil
}

func (link *Link) Lease() Lease {
	return Lease{
		Address: append(net.IP(nil), link.lease.Address...), Mask: append(net.IPMask(nil), link.lease.Mask...),
		Gateway: append(net.IP(nil), link.lease.Gateway...), DNS: append(net.IP(nil), link.lease.DNS...),
		LeaseTime: link.lease.LeaseTime,
	}
}

func (link *Link) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	select {
	case <-link.done:
		return nil, link.closedError()
	default:
	}
	if network == "tcp" || network == "tcp4" {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		hostIP := net.ParseIP(strings.Trim(host, "[]"))
		if hostIP == nil {
			addresses, err := link.lookupIPv4(ctx, host)
			if err != nil {
				return nil, err
			}
			var lastErr error
			for _, value := range addresses {
				if routeErr := link.validateIPv4Route(net.IP(value.AsSlice())); routeErr != nil {
					lastErr = routeErr
					continue
				}
				connection, dialErr := link.network.DialContext(ctx, "tcp4", net.JoinHostPort(value.String(), port))
				if dialErr == nil {
					return connection, nil
				}
				lastErr = dialErr
			}
			return nil, lastErr
		}
		if ipv4 := hostIP.To4(); ipv4 != nil {
			if err := link.validateIPv4Route(ipv4); err != nil {
				return nil, err
			}
		}
	}
	return link.network.DialContext(ctx, network, address)
}

func (link *Link) validateIPv4Route(destination net.IP) error {
	if sameSubnet(link.lease.Address, destination, link.lease.Mask) {
		return nil
	}
	if link.lease.Gateway.To4() == nil {
		return fmt.Errorf("隔离隧道 DHCP 未提供默认网关，无法访问子网外目标 %s", destination)
	}
	return nil
}

func (link *Link) Done() <-chan struct{} { return link.done }

func (link *Link) Err() error {
	link.errMu.RLock()
	defer link.errMu.RUnlock()
	return link.err
}

func (link *Link) Close() error {
	link.stop(net.ErrClosed)
	return nil
}

func (link *Link) inboundLoop() {
	for {
		select {
		case frame := <-link.session.Frames():
			if err := link.handleInbound(frame); err != nil {
				link.stop(err)
				return
			}
		case <-link.session.Done():
			return
		case <-link.done:
			return
		}
	}
}

func (link *Link) handleInbound(frame []byte) error {
	if len(frame) < 14 {
		return nil
	}
	switch binary.BigEndian.Uint16(frame[12:14]) {
	case 0x0806:
		return link.handleARP(frame)
	case 0x0800:
		if len(frame) < 34 || (!equalMAC(frame[0:6], link.mac[:]) && !isBroadcastMAC(frame[0:6])) {
			return nil
		}
		_, err := link.device.Write([][]byte{frame[14:]}, 0)
		return err
	default:
		return nil
	}
}

func (link *Link) handleARP(frame []byte) error {
	if len(frame) < 42 || binary.BigEndian.Uint16(frame[14:16]) != 1 || binary.BigEndian.Uint16(frame[16:18]) != 0x0800 || frame[18] != 6 || frame[19] != 4 {
		return nil
	}
	senderIP := net.IP(frame[28:32]).To4()
	if senderIP != nil && !senderIP.Equal(net.IPv4zero) {
		var key [4]byte
		var value [6]byte
		copy(key[:], senderIP)
		copy(value[:], frame[22:28])
		link.arpMu.Lock()
		link.arpTable[key] = value
		link.arpMu.Unlock()
	}
	if binary.BigEndian.Uint16(frame[20:22]) != 1 || !net.IP(frame[38:42]).Equal(link.lease.Address) {
		return nil
	}
	reply := make([]byte, 42)
	copy(reply[0:6], frame[6:12])
	copy(reply[6:12], link.mac[:])
	binary.BigEndian.PutUint16(reply[12:14], 0x0806)
	binary.BigEndian.PutUint16(reply[14:16], 1)
	binary.BigEndian.PutUint16(reply[16:18], 0x0800)
	reply[18], reply[19] = 6, 4
	binary.BigEndian.PutUint16(reply[20:22], 2)
	copy(reply[22:28], link.mac[:])
	copy(reply[28:32], link.lease.Address.To4())
	copy(reply[32:38], frame[22:28])
	copy(reply[38:42], frame[28:32])
	return link.session.Send(reply)
}

func (link *Link) outboundLoop() {
	buffer := make([]byte, 65535)
	buffers := [][]byte{buffer}
	sizes := make([]int, 1)
	for {
		count, err := link.device.Read(buffers, sizes, 0)
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				link.stop(err)
			}
			return
		}
		if count == 0 || sizes[0] < 20 {
			continue
		}
		packet := append([]byte(nil), buffer[:sizes[0]]...)
		if packet[0]>>4 != 4 {
			continue
		}
		if err := link.sendIPv4(packet); err != nil {
			link.stop(err)
			return
		}
	}
}

func (link *Link) sendIPv4(packet []byte) error {
	destination := net.IP(packet[16:20]).To4()
	if destination == nil {
		return nil
	}
	nextHop := destination
	if !sameSubnet(link.lease.Address, destination, link.lease.Mask) {
		nextHop = link.lease.Gateway.To4()
		if nextHop == nil {
			return errors.New("DHCP 未提供访问目标网络所需的网关")
		}
	}
	var key [4]byte
	copy(key[:], nextHop)
	link.arpMu.RLock()
	destinationMAC, resolved := link.arpTable[key]
	link.arpMu.RUnlock()
	if !resolved {
		destinationMAC = [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
		_ = link.session.Send(buildARPRequest(link.mac, link.lease.Address, nextHop))
	}
	frame := make([]byte, 14+len(packet))
	copy(frame[0:6], destinationMAC[:])
	copy(frame[6:12], link.mac[:])
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)
	copy(frame[14:], packet)
	return link.session.Send(frame)
}

func (link *Link) stop(reason error) {
	link.stopOnce.Do(func() {
		link.errMu.Lock()
		link.err = reason
		link.errMu.Unlock()
		close(link.done)
		_ = link.device.Close()
		_ = link.session.Close()
	})
}

func (link *Link) closedError() error {
	if err := link.Err(); err != nil {
		return err
	}
	return net.ErrClosed
}

type dhcpMessage struct {
	messageType byte
	address     net.IP
	serverID    net.IP
	mask        net.IPMask
	gateway     net.IP
	dns         net.IP
	leaseTime   time.Duration
}

func acquireDHCP(ctx context.Context, session *Session, mac [6]byte) (Lease, error) {
	var transactionBytes [4]byte
	if _, err := rand.Read(transactionBytes[:]); err != nil {
		return Lease{}, err
	}
	transactionID := binary.BigEndian.Uint32(transactionBytes[:])
	if err := session.Send(buildDHCPFrame(mac, transactionID, 1, nil, nil)); err != nil {
		return Lease{}, err
	}
	offer, err := waitDHCP(ctx, session, transactionID, 2, 10*time.Second)
	if err != nil {
		return Lease{}, fmt.Errorf("等待 DHCP Offer 失败: %w", err)
	}
	if err := session.Send(buildDHCPFrame(mac, transactionID, 3, offer.address, offer.serverID)); err != nil {
		return Lease{}, err
	}
	ack, err := waitDHCP(ctx, session, transactionID, 5, 10*time.Second)
	if err != nil {
		return Lease{}, fmt.Errorf("等待 DHCP Ack 失败: %w", err)
	}
	if len(ack.mask) != 4 {
		return Lease{}, errors.New("DHCP 未返回 IPv4 子网掩码")
	}
	return Lease{Address: ack.address, Mask: ack.mask, Gateway: ack.gateway, DNS: ack.dns, LeaseTime: ack.leaseTime}, nil
}

func waitDHCP(ctx context.Context, session *Session, transactionID uint32, messageType byte, timeout time.Duration) (dhcpMessage, error) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		select {
		case frame := <-session.Frames():
			message, ok := parseDHCPFrame(frame, transactionID)
			if ok && message.messageType == messageType {
				return message, nil
			}
		case <-session.Done():
			return dhcpMessage{}, session.Err()
		case <-ctx.Done():
			return dhcpMessage{}, ctx.Err()
		case <-timer.C:
			return dhcpMessage{}, context.DeadlineExceeded
		}
	}
}

func buildDHCPFrame(mac [6]byte, transactionID uint32, messageType byte, requestedIP, serverID net.IP) []byte {
	dhcp := make([]byte, 240, 320)
	dhcp[0], dhcp[1], dhcp[2] = 1, 1, 6
	binary.BigEndian.PutUint32(dhcp[4:8], transactionID)
	binary.BigEndian.PutUint16(dhcp[10:12], 0x8000)
	copy(dhcp[28:34], mac[:])
	copy(dhcp[236:240], []byte{99, 130, 83, 99})
	dhcp = append(dhcp, 53, 1, messageType, 61, 7, 1)
	dhcp = append(dhcp, mac[:]...)
	if ip := requestedIP.To4(); ip != nil {
		dhcp = append(dhcp, 50, 4)
		dhcp = append(dhcp, ip...)
	}
	if ip := serverID.To4(); ip != nil {
		dhcp = append(dhcp, 54, 4)
		dhcp = append(dhcp, ip...)
	}
	dhcp = append(dhcp, 55, 6, 1, 3, 6, 15, 28, 51, 255)
	for len(dhcp) < 300 {
		dhcp = append(dhcp, 0)
	}
	udp := make([]byte, 8+len(dhcp))
	binary.BigEndian.PutUint16(udp[0:2], 68)
	binary.BigEndian.PutUint16(udp[2:4], 67)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], dhcp)
	ipv4 := make([]byte, 20+len(udp))
	ipv4[0], ipv4[8], ipv4[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(ipv4[2:4], uint16(len(ipv4)))
	binary.BigEndian.PutUint16(ipv4[6:8], 0x4000)
	copy(ipv4[16:20], net.IPv4bcast.To4())
	binary.BigEndian.PutUint16(ipv4[10:12], checksum(ipv4[:20]))
	copy(ipv4[20:], udp)
	frame := make([]byte, 14+len(ipv4))
	copy(frame[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(frame[6:12], mac[:])
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)
	copy(frame[14:], ipv4)
	return frame
}

func parseDHCPFrame(frame []byte, transactionID uint32) (dhcpMessage, bool) {
	if len(frame) < 14+20+8+240 || binary.BigEndian.Uint16(frame[12:14]) != 0x0800 {
		return dhcpMessage{}, false
	}
	ipOffset := 14
	ipHeaderLength := int(frame[ipOffset]&0x0f) * 4
	if ipHeaderLength < 20 || len(frame) < ipOffset+ipHeaderLength+8+240 || frame[ipOffset+9] != 17 {
		return dhcpMessage{}, false
	}
	udpOffset := ipOffset + ipHeaderLength
	if binary.BigEndian.Uint16(frame[udpOffset:udpOffset+2]) != 67 || binary.BigEndian.Uint16(frame[udpOffset+2:udpOffset+4]) != 68 {
		return dhcpMessage{}, false
	}
	dhcp := frame[udpOffset+8:]
	if dhcp[0] != 2 || binary.BigEndian.Uint32(dhcp[4:8]) != transactionID || !equalBytes(dhcp[236:240], []byte{99, 130, 83, 99}) {
		return dhcpMessage{}, false
	}
	message := dhcpMessage{address: append(net.IP(nil), dhcp[16:20]...)}
	for index := 240; index < len(dhcp); {
		code := dhcp[index]
		index++
		if code == 0 {
			continue
		}
		if code == 255 || index >= len(dhcp) {
			break
		}
		length := int(dhcp[index])
		index++
		if index+length > len(dhcp) {
			break
		}
		value := dhcp[index : index+length]
		index += length
		switch code {
		case 1:
			if len(value) == 4 {
				message.mask = append(net.IPMask(nil), value...)
			}
		case 3:
			if len(value) >= 4 {
				message.gateway = append(net.IP(nil), value[:4]...)
			}
		case 6:
			if len(value) >= 4 {
				message.dns = append(net.IP(nil), value[:4]...)
			}
		case 51:
			if len(value) == 4 {
				message.leaseTime = time.Duration(binary.BigEndian.Uint32(value)) * time.Second
			}
		case 53:
			if len(value) == 1 {
				message.messageType = value[0]
			}
		case 54:
			if len(value) == 4 {
				message.serverID = append(net.IP(nil), value...)
			}
		}
	}
	return message, message.messageType != 0 && message.address.To4() != nil
}

func buildARPRequest(mac [6]byte, sourceIP, targetIP net.IP) []byte {
	request := make([]byte, 42)
	copy(request[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(request[6:12], mac[:])
	binary.BigEndian.PutUint16(request[12:14], 0x0806)
	binary.BigEndian.PutUint16(request[14:16], 1)
	binary.BigEndian.PutUint16(request[16:18], 0x0800)
	request[18], request[19] = 6, 4
	binary.BigEndian.PutUint16(request[20:22], 1)
	copy(request[22:28], mac[:])
	copy(request[28:32], sourceIP.To4())
	copy(request[38:42], targetIP.To4())
	return request
}

func randomMAC() ([6]byte, error) {
	var value [6]byte
	if _, err := rand.Read(value[:]); err != nil {
		return value, err
	}
	value[0] = 0x5e
	return value, nil
}

func sameSubnet(left, right net.IP, mask net.IPMask) bool {
	left4, right4 := left.To4(), right.To4()
	if left4 == nil || right4 == nil || len(mask) != 4 {
		return false
	}
	for index := 0; index < 4; index++ {
		if left4[index]&mask[index] != right4[index]&mask[index] {
			return false
		}
	}
	return true
}

func checksum(data []byte) uint16 {
	var sum uint32
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	if len(data) == 1 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func equalMAC(left, right []byte) bool { return equalBytes(left, right) && len(left) == 6 }

func isBroadcastMAC(value []byte) bool {
	return equalMAC(value, []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
