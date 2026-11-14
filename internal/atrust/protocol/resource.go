// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 hygkui and contributors
// LabRemote 适配：2026-11-14，进程内目标 TCP 通道；修改记录见 MODIFICATIONS.md。

package atrust

// resource.go — 把资源树投影成 UI 能直接渲染的形状。
//
// 为什么要单独一层：/controller/v1/user/clientResource 的响应结构尚未与
// 真实网关逐字段比对过（mock 只提供了最小可用集，规范 §8.1 提到资源在
// appList / appListV2 里）。直接把这个 map 交给 UI 会让"猜错字段名"
// 变成静默的空列表，而不是一个可以定位的问题。
//
// 所以这里做**宽容解析**：按已知的几个位置依次找数组，找到就用，
// 找不到就返回空切片并把原始键名记下来。这样对未知形状不会崩，
// 而且排查时能看到网关到底给了什么。

import (
	"encoding/json"
	"fmt"
)

// Resource 是 UI 侧的资源视图。
//
// 字段名（json tag）与 V5VPN 侧的 protocol.VPNResource 保持一致，
// 目的是让前端复用同一个渲染函数。两个包之间没有类型依赖——
// 这里只是让序列化后的形状相同。
type Resource struct {
	Name       string `json:"name"`
	Protocol   string `json:"protocol"`
	RemoteIP   string `json:"remoteIp"`
	RemotePort string `json:"remotePort"`
	LocalProxy string `json:"localProxy"`
	Status     string `json:"status"`
	MapID      string `json:"mapId,omitempty"`
	AccessURL  string `json:"accessUrl,omitempty"`
}

// resourceArrayKeys 是可能直接承载资源数组的键，按可信度排列。
//
// 来源：aTrustCore.dll 的 JSON Schema 与 §8.1 的字段表。
// appListV2 优先于 appList —— V2 是当前版本，V1 是兼容路径。
var resourceArrayKeys = []string{
	"appListV2",
	"appList",
	"resource",
	"resources",
	"appListInfo",
}

// appInfoKey 是真实资源树的入口键。
//
// 真实结构是三层嵌套（geektrust §4.2 与 libreatrust resource.rs 一致）：
//
//	data.appList.data.appInfo[]    ← 资源分组
//	              .apps[]          ← 具体应用
//	              .addressList[]   ← 路由条目 {protocol, port, host}
//
// 也就是说 appList 名下不是数组而是又一个 {code, data} 包装层。
// 早期实现只认「appList 直接是数组」，于是真实响应会被判成空列表，
// 且没有任何报错——这正是 §28.6 记的那个空白。
const appInfoKey = "appInfo"

// resourceTreeKeys 是「appList 这类键名下可能是 {code,data:{appInfo}} 」的候选。
//
// 与 resourceArrayKeys 的区别：那一组假设键名**直接**对应数组，
// 这一组假设键名对应的是分组树。两者形状不同，必须先试树、再试扁平数组，
// 否则一个真实的资源树会被判成空列表。
var resourceTreeKeys = []string{
	"appListV2",
	"appList",
	"resource",
}

// ExtractResources 从资源树原始响应里投影出资源列表。
//
// 返回值 extraKeys 是响应里出现但未被识别的顶层键，供调用方记录——
// 它的用途是：如果真实网关用的键不在已知集合里，日志里能直接看到候选，
// 而不是只看到一个空列表。
func ExtractResources(raw map[string]any) (items []Resource, extraKeys []string) {
	if raw == nil {
		return []Resource{}, nil
	}

	// 先按真实的分组树解析（§4.2），失败再退回「键名直接是数组」的旧形状。
	if fromTree, ok := resourcesFromTree(raw); ok {
		return fromTree, unrecognizedKeys(raw)
	}
	if fromFlat, ok := resourcesFromFlatArrays(raw); ok {
		return fromFlat, unrecognizedKeys(raw)
	}
	return []Resource{}, unrecognizedKeys(raw)
}

// unrecognizedKeys 列出 raw 里不属于任何已知资源键的顶层键。
func unrecognizedKeys(raw map[string]any) []string {
	known := make(map[string]bool, len(resourceArrayKeys)+len(resourceTreeKeys))
	for _, k := range resourceArrayKeys {
		known[k] = true
	}
	for _, k := range resourceTreeKeys {
		known[k] = true
	}

	var extra []string
	for k := range raw {
		if !known[k] {
			extra = append(extra, k)
		}
	}
	return extra
}

// resourcesFromTree 解析 data.appList.data.appInfo[].apps[].addressList[] 结构。
//
// 两处「可省」的包装都容忍：
//   - 键名下可能直接是 {appInfo:[...]}，也可能再包一层 {code,data:{appInfo:[...]}}
//   - appInfo 也可能直接挂在顶层
func resourcesFromTree(raw map[string]any) ([]Resource, bool) {
	if groups, ok := appInfoArray(raw); ok {
		return resourcesFromGroups(groups), true
	}
	for _, key := range resourceTreeKeys {
		v, ok := raw[key]
		if !ok {
			continue
		}
		m, isMap := v.(map[string]any)
		if !isMap {
			continue
		}
		// 有的网关把 payload 包在 {"code":0,"data":{...}} 里。
		if inner, has := m["data"]; has {
			if groups, ok := appInfoArray(inner); ok {
				return resourcesFromGroups(groups), true
			}
		}
		if groups, ok := appInfoArray(m); ok {
			return resourcesFromGroups(groups), true
		}
	}
	return nil, false
}

// appInfoArray 从 v 里取出 appInfo 数组。
func appInfoArray(v any) ([]any, bool) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, false
	}
	arr, ok := m[appInfoKey].([]any)
	return arr, ok
}

// resourcesFromGroups 展开资源分组。
//
// 一个 app 可能带多条 addressList（同一应用的不同入口，比如域名 + 内网 IP）。
// 这里**每条地址投影成一行**：界面看到的是路由表，而不是应用清单。
// 这样「这个应用到底被映射到哪些地址」是直接可读的，排查时不用再点开。
func resourcesFromGroups(groups []any) []Resource {
	out := make([]Resource, 0, len(groups))
	for _, g := range groups {
		gm, ok := g.(map[string]any)
		if !ok {
			continue
		}
		groupName := firstString(gm, "name", "appName", "title")
		apps, _ := gm["apps"].([]any)
		for _, a := range apps {
			am, ok := a.(map[string]any)
			if !ok {
				continue
			}
			out = append(out, resourcesFromApp(am, groupName)...)
		}
	}
	return out
}

// resourcesFromApp 把一个应用展开成若干行资源。
func resourcesFromApp(app map[string]any, groupName string) []Resource {
	name := firstString(app, "name", "appName", "title")
	if name == "" {
		// 应用没名字时用分组名兜底：界面上至少知道它属于哪一组。
		name = groupName
	}
	id := firstString(app, "id", "appId")
	accessURL := firstString(app, "accessAddress", "accessUrl", "accessURL")

	addrs, _ := app["addressList"].([]any)
	if len(addrs) == 0 {
		// 没有 addressList 的应用仍然有名字与入口地址，保留一行
		// 总比丢掉它好——丢掉了就完全看不到这个应用存在过。
		return []Resource{{
			Name:      name,
			Protocol:  "tcp",
			Status:    "active",
			MapID:     id,
			AccessURL: accessURL,
		}}
	}

	out := make([]Resource, 0, len(addrs))
	for _, e := range addrs {
		em, ok := e.(map[string]any)
		if !ok {
			continue
		}
		r := Resource{
			Name:       name,
			Protocol:   firstString(em, "protocol", "proto"),
			RemoteIP:   firstString(em, "host", "address", "domain"),
			RemotePort: firstString(em, "port", "destPort"),
			Status:     "active",
			MapID:      id,
			AccessURL:  accessURL,
		}
		if r.Protocol == "" {
			r.Protocol = "tcp"
		}
		// aTrust 用 port "0" 表示「全部端口」，直接显示 :0 会让人误以为是
		// 一个真实端口号。用 "*" 表示通配更准确。
		if r.RemotePort == "0" {
			r.RemotePort = "*"
		}
		out = append(out, r)
	}
	return out
}

// resourcesFromFlatArrays 是早期假设的形状：键名下直接是资源数组。
//
// 保留它是为了兼容 appListV2 等尚未见到实例的网关版本——真实网关目前
// 走的是 resourcesFromTree，但换个部署就可能是扁平数组。
func resourcesFromFlatArrays(raw map[string]any) ([]Resource, bool) {
	for _, key := range resourceArrayKeys {
		v, ok := raw[key]
		if !ok {
			continue
		}
		// 有的网关把数组包在 {"code":0,"data":[...]} 里。
		if m, isMap := v.(map[string]any); isMap {
			if inner, has := m["data"]; has {
				v = inner
			}
		}
		arr, isArr := v.([]any)
		if !isArr {
			continue
		}
		items := make([]Resource, 0, len(arr))
		for _, elem := range arr {
			m, ok := elem.(map[string]any)
			if !ok {
				continue
			}
			items = append(items, resourceFromMap(m))
		}
		return items, true
	}
	return nil, false
}

// resourceFromMap 从单个资源条目里尽力提取字段。
//
// 每个字段都试多个候选键名：aTrust 的不同版本/不同网关在命名上并不统一
// （host vs addr vs ip，port 可能是数字也可能是字符串）。
func resourceFromMap(m map[string]any) Resource {
	r := Resource{
		Name:       firstString(m, "name", "appName", "resourceName", "title"),
		Protocol:   firstString(m, "protocol", "type", "appType"),
		RemoteIP:   firstString(m, "host", "addr", "ip", "address", "domain"),
		RemotePort: firstString(m, "port", "remotePort", "destPort"),
		AccessURL:  firstString(m, "accessUrl", "url", "accessURL"),
		MapID:      firstString(m, "mapId", "id", "appId"),
	}
	r.LocalProxy = firstString(m, "localProxy", "localAddr", "proxy")

	if r.Name == "" {
		// 没有名字的资源在界面上不可用；用地址兜底，避免一条空行。
		r.Name = r.RemoteIP
	}
	// 扁平数组形态里 protocol 常常整个缺失（{"name","host","port"}）。
	// 留空会让上层把它当成"非 TCP"跳过，表现为资源在列表里但没有本地代理。
	// 与 resourcesFromApp 的处理保持一致：缺省即 TCP。
	if r.Protocol == "" {
		r.Protocol = "tcp"
	}
	r.Status = "active"
	return r
}

// firstString 返回第一个存在且可转成字符串的值。
//
// 数字类型的端口很常见（"port": 443），所以要处理 json.Number 与 float64。
func firstString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		v, ok := m[k]
		if !ok || v == nil {
			continue
		}
		switch t := v.(type) {
		case string:
			if t != "" {
				return t
			}
		case json.Number:
			return t.String()
		case float64:
			// 443.0 要输出成 "443" 而不是 "443.000000"
			if t == float64(int64(t)) {
				return fmt.Sprintf("%d", int64(t))
			}
			return fmt.Sprintf("%g", t)
		case bool:
			// 布尔值不是有意义的地址/名称，跳过。
			continue
		}
	}
	return ""
}
