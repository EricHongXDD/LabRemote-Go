// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 hygkui and contributors
// LabRemote 适配：2026-11-14，进程内目标 TCP 通道；修改记录见 MODIFICATIONS.md。

// Package atrust implements the Sangfor aTrust (零信任) control-plane protocol
// as a client.
//
// This package is deliberately self-contained: it must not import
// internal/protocol or internal/proxy, which belong to the V5VPN backend.
// The two backends share nothing at the code level — they only share the
// product surface above them (service + UI). See ATRUST_PROTOCOL_ANALYSIS.md
// §14.5.2 for the three hard boundaries this enforces.
//
// The protocol was derived from the official aTrustTray client and validated
// by driving that official client against a mock gateway we implemented from
// the spec (see the same document, §21–§27). Phases covered here:
//
//	GET  /public/manifest              capability negotiation
//	GET  /public/manifest.js           entranceConfig (JavaScript, not JSON)
//	GET  /passport/v1/public/authConfig   35 flat keys
//	POST /passport/v1/auth/psw        RSA password auth
//	GET  /passport/v1/auth/authCheck  nextService continuation
//	GET  /passport/v1/user/onlineInfo online state
//	POST /controller/v1/user/clientResource   resource tree
//	POST /passport/v1/public/sessionIdExchange  form-encoded
//	POST /passport/v1/public/ticketExchange     form-encoded
//	POST /passport/v1/user/logout     logout
//
// Not implemented, by design: the anti-MITM signature subsystem
// (X-Request-Sig / X-Response-Sig). It only matters on gateways with
// antiMITMAttackData.enable=1, and the official client does not require it
// for login on enable=0 gateways (§11.1.5, §27.5).
package atrust
