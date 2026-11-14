// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 hygkui and contributors
// LabRemote 适配：2026-11-14，进程内目标 TCP 通道；修改记录见 MODIFICATIONS.md。

package atrust

// route.go — 资源树 → 路由索引，以及数据面接入线路的解析。
//
// 数据面要回答两个问题，答案都在资源树里：
//
//	1. 目标 host:port 属于哪个 appId、哪个 nodeGroup？
//	   → addressList[] 是路由策略，appId 是网关侧的鉴权依据
//	2. 这个 nodeGroup 的接入线路在哪？
//	   → config.nodeGroupConf.nodeGroupList[].addressInfo[]
//
// 本文件把这两个问题做成一个索引，避免每建一条连接都去遍历整棵树。
//
// ⚠ 路由匹配规则（geektrust §4.2）不是简单的字符串相等：
//
//	IP 字面量  → 直接查 IP 规则
//	域名       → 先查精确映射；未命中则解析 IPv4 再查 IP 规则；
//	             最后才用后缀通配符
//	IP 规则里 精确地址 > CIDR/区间（覆盖范围越小越优先）
//
// 这里实现了精确 IP、CIDR、闭区间与后缀通配符四类。geektrust 提到的
// "其他通配符形式暂不匹配"同样适用——宁可直连失败，也不要错误地把
// 一个不该走隧道的目标塞进隧道。

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// routeEntry 是一条路由规则。
type routeEntry struct {
	AppID       string
	NodeGroupID string
	Protocol    string
	// kind: "exact"（主机名或 IP 字面量）/ "cidr" / "range" / "suffix"
	Kind string
	// value 的含义随 kind 变化：
	//   exact  → 主机名或 IP
	//   cidr   → 网络地址/前缀长度
	//   range  → "start-end"
	//   suffix → ".example.com"
	Value string
	// Port 为 0 表示通配（资源树里 port "0"）。
	Port  int
	Ports string
}

// resourceIndex 是解析后的资源路由表。
type resourceIndex struct {
	entries []routeEntry

	// nodeAddrs 是 nodeGroupId → "host:port" 的接入线路。
	nodeAddrs map[string]string
	// defaultNode 是 majorNodeGroup.id 对应的线路，资源条目没写 nodeGroupId 时用它。
	defaultNode string
	// firstAppID 是整棵树里第一个应用的 id。
	//
	// 用途：隧道认证 JSON 的 appId 字段。真实网关按应用鉴权，但某些资源
	// （如整段网段）在资源树里的粒度就是"组"，此时用该组的首个应用占位——
	// 这比留空更接近官方客户端的行为。
	firstAppID string

	// resolver 把域名解析成 IP，用于「域名 → IP 规则」这一轮匹配。
	//
	// 抽成字段而不是直接调 net.LookupIP，是因为它会在**每次**未命中
	// 精确规则时触发一次 DNS 查询：联调时目标不可达会因此卡住十几秒，
	// 测试里也会变成真实网络请求。nil 表示不做域名解析（只用精确规则
	// 与后缀规则），这也是构造索引时的默认值。
	resolver func(host string) net.IP

	// gatewayHost 是控制面网关的主机部分，用于展开线路地址里的
	// {{sdpcHost}} 占位符（见 expandPlaceholder）。为空时占位符无法展开，
	// 相关线路会被跳过。
	gatewayHost string
}

// buildResourceIndex 从 clientResource 的原始响应构造索引。
//
// 结构是 data.appList.data.appInfo[]（分组）.apps[]（应用）.addressList[]（路由）。
// 各层都做宽容处理：任何一个键缺失都不会 panic，只是那条规则不生效。
//
// gatewayHost 用于展开线路地址里的 {{sdpcHost}} 占位符；传空串时
// 那些线路会被跳过（见 expandPlaceholder）。
func buildResourceIndex(raw map[string]any, gatewayHost string) *resourceIndex {
	idx := &resourceIndex{
		nodeAddrs:   map[string]string{},
		gatewayHost: gatewayHost,
	}
	if raw == nil {
		return idx
	}

	data := childMap(raw, "appList")
	if data == nil {
		// 兼容：有的网关把 appList 的内容直接挂在顶层。
		data = raw
	}
	if inner := childMap(data, "data"); inner != nil {
		data = inner
	}

	// 线路：data.config.nodeGroupConf
	if cfg := childMap(data, "config"); cfg != nil {
		if ngc := childMap(cfg, "nodeGroupConf"); ngc != nil {
			idx.parseNodeGroups(ngc)
		}
	}

	for _, g := range childArray(data, "appInfo") {
		gm, ok := g.(map[string]any)
		if !ok {
			continue
		}
		groupNode := firstString(gm, "nodeGroupId", "nodeGroupID")
		for _, a := range childArray(gm, "apps") {
			am, ok := a.(map[string]any)
			if !ok {
				continue
			}
			appID := firstString(am, "id", "appId")
			if idx.firstAppID == "" && appID != "" {
				idx.firstAppID = appID
			}
			appNode := firstString(am, "nodeGroupId", "nodeGroupID")
			if appNode == "" {
				appNode = groupNode
			}
			if appNode == "" {
				appNode = idx.defaultNode
			}
			proto := strings.ToLower(firstString(am, "accessModel", "subModel"))
			if proto == "" {
				proto = "tcp"
			}
			for _, ae := range childArray(am, "addressList") {
				em, ok := ae.(map[string]any)
				if !ok {
					continue
				}
				idx.addAddress(em, appID, appNode)
			}
		}
	}
	return idx
}

// sdpcHostPlaceholder 是"网关自身地址"的占位符。
//
// 有的网关（以及 mock）在 addressInfo.address 里不写具体主机，而是给这个
// 占位符，由客户端替换成它正在连接的那个网关地址。好处是同一条资源树
// 在任意入口下都成立：本机连 127.0.0.1、远端连公网 IP 都能用。
//
// 真实网关用它的场景是"控制面与数据面同一台机器但地址下发时要保持中立"。
const sdpcHostPlaceholder = "{{sdpcHost}}"

// expandPlaceholder 把线路地址里的 {{sdpcHost}} 换成网关主机。
//
// ★ 只替换**主机部分**，端口保持资源树给的原样。
// 控制面通常连在 :8443，数据面固定 :441，直接把控制面的 host:port 拼上去
// 会得到 "127.0.0.1:8443:441" 这种畸形地址。
//
// 网关主机为空（比如调用方没给 baseURL）时返回空串——调用方据此跳过
// 这条线路，而不是把字面量 "{{sdpcHost}}" 交给 DNS 去解析（那样报出来的
// "no such host" 会掩盖真正的配置问题）。
func (r *resourceIndex) expandPlaceholder(addr string) string {
	if !strings.Contains(addr, sdpcHostPlaceholder) {
		return addr
	}
	host := r.gatewayHost
	if host == "" {
		return ""
	}
	return strings.ReplaceAll(addr, sdpcHostPlaceholder, host)
}

// parseNodeGroups 解析 config.nodeGroupConf。
//
// 线路地址的两种写法都接受：
//
//	addressInfo[].{type:"wan", address:"host:441"}
//	addressInfo[].address 为 "{{sdpcHost}}:441"  → 替换成网关主机
//
// 后一种是 mock 用的：它让同一条资源树在本机和远端都能用。
func (r *resourceIndex) parseNodeGroups(ngc map[string]any) {
	if major := childMap(ngc, "majorNodeGroup"); major != nil {
		r.defaultNode = firstString(major, "id")
	}

	for _, g := range childArray(ngc, "nodeGroupList") {
		gm, ok := g.(map[string]any)
		if !ok {
			continue
		}
		id := firstString(gm, "id", "groupID")
		if id == "" {
			continue
		}
		for _, a := range childArray(gm, "addressInfo") {
			am, ok := a.(map[string]any)
			if !ok {
				continue
			}
			// type 非 "wan" 的线路不可用（内网/专线等其他类型被客户端忽略）。
			if t := firstString(am, "type"); t != "" && t != "wan" {
				continue
			}
			addr := firstString(am, "address", "addr")
			if addr == "" {
				continue
			}
			addr = r.expandPlaceholder(addr)
			if addr == "" {
				// 占位符没解析出来：跳过这条线路，而不是把字面量当主机名。
				continue
			}
			if !strings.Contains(addr, ":") {
				addr += ":441"
			}
			if _, exists := r.nodeAddrs[id]; !exists {
				r.nodeAddrs[id] = addr
			}
		}
	}
}

// addAddress 把一条 addressList 条目加进索引。
func (r *resourceIndex) addAddress(em map[string]any, appID, nodeGroup string) {
	host := firstString(em, "host", "address", "domain", "ip")
	if host == "" {
		// 有的形状是 {"ip": ["10.0.0.1"], ...}，把数组元素当作地址。
		if ips := childArray(em, "ip"); len(ips) > 0 {
			for _, v := range ips {
				if s, ok := v.(string); ok && s != "" {
					r.addAddressValue(s, em, appID, nodeGroup)
				}
			}
			return
		}
		return
	}
	r.addAddressValue(host, em, appID, nodeGroup)
}

// addAddressValue 按地址形态归类并存入规则。
func (r *resourceIndex) addAddressValue(host string, em map[string]any, appID, nodeGroup string) {
	proto := strings.ToLower(firstString(em, "protocol", "proto"))
	if proto == "" {
		proto = "tcp"
	}
	ports := firstString(em, "port", "destPort")
	port := parsePort(ports)
	if port <= 0 {
		port = 0 // 通配
	}

	entry := routeEntry{AppID: appID, NodeGroupID: nodeGroup, Protocol: proto, Port: port, Ports: ports}

	switch {
	case strings.HasPrefix(host, "*."):
		entry.Kind = "suffix"
		entry.Value = strings.ToLower(host[1:]) // 保留前导点

	case strings.Contains(host, "/"):
		if _, _, err := net.ParseCIDR(host); err == nil {
			entry.Kind = "cidr"
			entry.Value = host
		} else {
			return
		}

	case isClosedRange(host):
		entry.Kind = "range"
		entry.Value = host

	default:
		entry.Kind = "exact"
		entry.Value = strings.ToLower(host)
	}

	r.entries = append(r.entries, entry)
}

// lookup 按目标 host:port 查路由。
//
// 返回的 bool 表示是否命中。命中的规则携带 appId 与 nodeGroup。
func (r *resourceIndex) lookup(host string, port int) (routeEntry, bool) {
	if r == nil {
		return routeEntry{}, false
	}
	host = strings.ToLower(strings.TrimSpace(host))

	ip := net.ParseIP(host)

	// 第一轮：精确匹配（IP 字面量或域名精确命中）。
	for _, e := range r.entries {
		if e.Kind != "exact" {
			continue
		}
		if e.Value != host {
			continue
		}
		if !e.matchesTCPPort(port) {
			continue
		}
		return e, true
	}

	// 第二轮：IP 规则（CIDR / 区间），仅当目标是 IP 字面量或能解析出 IP。
	//
	// 域名解析是可选的（见 resourceIndex.resolver 的注释）：未注入解析器时
	// 直接跳到后缀规则，避免一次 DNS 查询把调用卡住十几秒。
	if ip == nil && r.resolver != nil {
		ip = r.resolver(host)
	}
	if ip != nil {
		// 精确地址优先于 CIDR/区间；同级里覆盖范围小的优先。
		best := -1
		bestSize := -1
		for i, e := range r.entries {
			if !e.matchesTCPPort(port) {
				continue
			}
			var size int
			switch e.Kind {
			case "cidr":
				_, ipnet, err := net.ParseCIDR(e.Value)
				if err != nil || !ipnet.Contains(ip) {
					continue
				}
				ones, _ := ipnet.Mask.Size()
				size = ones
				if best == -1 || size > bestSize {
					best, bestSize = i, size
				}
			case "range":
				lo, hi, ok := splitRange(e.Value)
				if !ok || !inRange(ip, lo, hi) {
					continue
				}
				// 区间用地址数近似"精度"：范围越小越优先。
				span := ipToUint32(net.ParseIP(hi)) - ipToUint32(net.ParseIP(lo)) + 1
				size = 32 - bitsNeeded(span)
				if best == -1 || size > bestSize {
					best, bestSize = i, size
				}
			}
		}
		if best >= 0 {
			return r.entries[best], true
		}
	}

	// 第三轮：后缀通配符兜底。
	for _, e := range r.entries {
		if e.Kind != "suffix" {
			continue
		}
		if !e.matchesTCPPort(port) {
			continue
		}
		if strings.HasSuffix(host, e.Value) || host == strings.TrimPrefix(e.Value, ".") {
			return e, true
		}
	}

	return routeEntry{}, false
}

// matchesTCPPort 不能把 UDP 资源或无法解析的端口列表扩大为所有 TCP 端口。
func (e routeEntry) matchesTCPPort(port int) bool {
	switch strings.ToLower(e.Protocol) {
	case "", "tcp", "6", "any", "all", "ip", "0":
	default:
		return false
	}
	ports := strings.TrimSpace(e.Ports)
	if ports == "" {
		return e.Port == 0 || e.Port == port
	}
	for _, item := range strings.Split(ports, ",") {
		item = strings.TrimSpace(item)
		if item == "0" || item == "*" {
			return true
		}
		if first, last, found := strings.Cut(item, "-"); found {
			lo, err1 := strconv.Atoi(strings.TrimSpace(first))
			hi, err2 := strconv.Atoi(strings.TrimSpace(last))
			if err1 == nil && err2 == nil && lo >= 0 && hi <= 65535 && lo <= port && port <= hi {
				return true
			}
			continue
		}
		number, err := strconv.Atoi(item)
		if err == nil && number == port {
			return true
		}
	}
	return false
}

// nodeFor 返回规则对应线路的 host:port。
func (r *resourceIndex) nodeFor(e routeEntry) string {
	if r == nil {
		return ""
	}
	if e.NodeGroupID != "" {
		if a, ok := r.nodeAddrs[e.NodeGroupID]; ok {
			return a
		}
	}
	if r.defaultNode != "" {
		if a, ok := r.nodeAddrs[r.defaultNode]; ok {
			return a
		}
	}
	// 兜底：只有一条线路时直接用它。
	if len(r.nodeAddrs) == 1 {
		for _, a := range r.nodeAddrs {
			return a
		}
	}
	return ""
}

// gatewayHostOf 从 baseURL（形如 https://host:port）取出**纯主机部分**。
//
// 注意与 tunnel.go 的 hostOnly 区分：那个接收 host:port，这个接收带
// scheme 的 URL。混用会得到 "https://127.0.0.1" 这种含协议的主机名，
// 拼进线路地址后 dial 会报 "too many colons in address"。
func gatewayHostOf(baseURL string) string {
	u, err := url.Parse(baseURL)
	if err != nil || u.Hostname() == "" {
		return ""
	}
	return u.Hostname()
}

// lookupIPv4 把域名解析成首个 IPv4 地址，失败返回 nil。
//
// 只取 IPv4：资源树的 CIDR/区间规则都是 IPv4 形态，IPv6 结果对它们
// 没有意义，硬塞进去只会让 inRange 里的 32 位运算溢出。
func lookupIPv4(host string) net.IP {
	addrs, err := net.LookupIP(host)
	if err != nil {
		return nil
	}
	for _, a := range addrs {
		if v4 := a.To4(); v4 != nil {
			return v4
		}
	}
	return nil
}

// ---------- 地址判定小工具 ----------

func isClosedRange(s string) bool {
	lo, hi, ok := splitRange(s)
	return ok && lo != "" && hi != ""
}

func splitRange(s string) (string, string, bool) {
	i := strings.Index(s, "-")
	if i <= 0 || i == len(s)-1 {
		return "", "", false
	}
	lo, hi := strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+1:])
	if net.ParseIP(lo) == nil || net.ParseIP(hi) == nil {
		return "", "", false
	}
	return lo, hi, true
}

func inRange(ip net.IP, lo, hi string) bool {
	v := ipToUint32(ip)
	l := ipToUint32(net.ParseIP(lo))
	h := ipToUint32(net.ParseIP(hi))
	return v >= l && v <= h
}

func ipToUint32(ip net.IP) uint32 {
	v4 := ip.To4()
	if v4 == nil {
		return 0
	}
	return uint32(v4[0])<<24 | uint32(v4[1])<<16 | uint32(v4[2])<<8 | uint32(v4[3])
}

func bitsNeeded(n uint32) int {
	if n == 0 {
		return 0
	}
	bits := 0
	for n > 1 {
		n >>= 1
		bits++
	}
	return bits
}

// ---------- 通用取值辅助 ----------

// childMap 取一层 map。
func childMap(m map[string]any, key string) map[string]any {
	if m == nil {
		return nil
	}
	v, ok := m[key]
	if !ok || v == nil {
		return nil
	}
	cm, _ := v.(map[string]any)
	return cm
}

// childArray 取一层数组。
func childArray(m map[string]any, key string) []any {
	if m == nil {
		return nil
	}
	v, ok := m[key]
	if !ok || v == nil {
		return nil
	}
	arr, _ := v.([]any)
	return arr
}

// SetResources 记录资源树并把线路、appId 等派生信息写进 Client。
//
// 由 ClientResource / Login 自动调用；也可由调用方在自行解析后调用，
// 让 DialTCP 能选路。
func (c *Client) SetResources(raw map[string]any) {
	idx := buildResourceIndex(raw, gatewayHostOf(c.baseURL))
	// 生产路径才启用 DNS：域名若不在精确规则里，需要解析出 IP 去匹配
	// CIDR/区间规则（geektrust §4.2 的第二轮）。
	idx.resolver = lookupIPv4

	c.mu.Lock()
	c.resources = idx
	c.resourceShape = resourceShape(raw)
	c.currentAppID = idx.firstAppID
	if idx.defaultNode != "" {
		c.nodeAddr = idx.nodeAddrs[idx.defaultNode]
	}
	if c.nodeAddr == "" && len(idx.nodeAddrs) > 0 {
		for _, a := range idx.nodeAddrs {
			c.nodeAddr = a
			break
		}
	}
	c.mu.Unlock()

	if idx.firstAppID == "" {
		c.logf("aTrust 资源树里没有解析出 appId，数据面连接可能被网关拒绝")
	}
	if c.dataNode() == "" {
		c.logf("aTrust 资源树里没有可用的数据面线路（config.nodeGroupConf）")
	}
}

// DialResource 按资源条目直接建隧道。
//
// 与 DialTCP 的区别：这里用资源自带的 appId / nodeGroupId，不需要
// 再查路由表。适合上层已经知道要连哪个资源的场景。
func (c *Client) DialResource(ctx context.Context, host string, port int) (*TCPConn, error) {
	return c.DialTCP(ctx, host, port)
}

// TargetDiagnostics 仅返回资源结构、数量及当前目标的线路，不含账号或认证票据。
func (c *Client) TargetDiagnostics(host string, port int) map[string]any {
	c.mu.RLock()
	idx, shape := c.resources, append([]string(nil), c.resourceShape...)
	c.mu.RUnlock()
	details := map[string]any{"resource_shape": shape}
	if idx == nil {
		return details
	}
	entry, matched := idx.lookup(host, port)
	details["rule_count"], details["gateway_count"] = len(idx.entries), len(idx.nodeAddrs)
	details["target_matched"], details["gateway"] = matched, idx.nodeFor(entry)
	if matched {
		details["matched_protocol"], details["matched_ports"] = entry.Protocol, entry.Ports
		details["matched_address"], details["matched_kind"] = entry.Value, entry.Kind
	}
	return details
}

// resourceShape 记录字段类型以定位网关版本差异，禁止记录资源字段的值。
func resourceShape(raw map[string]any) []string {
	seen := map[string]bool{}
	var visit func(any, string, int)
	visit = func(value any, path string, depth int) {
		if depth > 10 || len(seen) >= 180 {
			return
		}
		switch v := value.(type) {
		case map[string]any:
			keys := make([]string, 0, len(v))
			for key := range v {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				if len(key) <= 48 {
					visit(v[key], path+"."+key, depth+1)
				}
			}
		case []any:
			seen[path+"[]"] = true
			for i, item := range v {
				if i >= 2 {
					break
				}
				visit(item, path+"[]", depth+1)
			}
		default:
			seen[path+":"+fmt.Sprintf("%T", value)] = true
		}
	}
	visit(raw, "resource", 0)
	keys := make([]string, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// String 便于日志输出。
func (r routeEntry) String() string {
	return fmt.Sprintf("%s:%s(app=%s,node=%s,port=%d)", r.Kind, r.Value, r.AppID, r.NodeGroupID, r.Port)
}
