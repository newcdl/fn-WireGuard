// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package service

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"strings"
)

// SettingInstallID 是本机的「安装标识」：首次使用时随机生成一次并落库。
//
// 它只需要「稳定、且跨机器大致不重复」这一点，用在两处：
//
//  1. 派生「按机器随机的网段基准」（见 defaultAddrOffset）—— 两台 NAS 的第 N 条连接
//     不再必然选到同一个隧道网段，也就不会出现「两端设备地址成对重复」；
//  2. 随邀请带出去，让对方一眼看出「两台机器是不是同一份数据装出来的」（见同源提示）。
//
// 为什么不做成「随备份还原一起走」：那正是「两台机器同源」的成因 —— 换机恢复后新机器
// 若沿用旧标识，它的默认网段又会与源机器撞在一起。所以 applyBackupPayload 刻意**跳过这一项**，
// 每台机器始终用自己的标识。也正因为如此，同源只可能来自「手工拷贝整机数据」，
// 那种情况由导入时的提示负责点破。
//
// 为什么不复用别的已有值：机器身份不该与任何业务地址/密钥绑在一起 ——
// 业务值会变（密钥可轮换、地址可修改），机器身份跟着变就会让「已建连接」与
// 「新建连接的默认网段」算出两套基准。
const SettingInstallID = "install_id"

// installID 返回本机的安装标识；首次调用时生成一次并落库。
//
// 读不到（库不可写等）时返回空串：调用方按「没有标识」处理，退回按连接序号分配的老行为，
// 只是两台机器可能撞车，不影响可用性 —— 为了一张「少踩坑」用的台账而让建连接失败，不值得。
func (s *Service) installID(ctx context.Context) string {
	if v := strings.TrimSpace(s.Store.GetSetting(ctx, SettingInstallID, "")); v != "" {
		return v
	}
	v := newToken(16)
	// 直接写存储：这是应用自己生成的内部值，不走「用户改设置」那条带审计与快照的路径
	//（它天然随机，进快照只会让「回滚配置会不会换标识」变得难以回答，而它对用户没有意义）。
	if err := s.Store.SetSetting(ctx, SettingInstallID, v); err != nil {
		s.Log.Warn("生成安装标识失败：本次新建连接的默认网段未做跨机去相关", "err", err)
		return ""
	}
	return v
}

// defaultAddrOffset 由本机安装标识派生一个稳定的「网段基准偏移」（0..addrSpan-1）。
//
// 为什么必须**稳定**：同一台机器每新建一条连接都要从同一个基准往后顺延，
// 否则每加一条连接都可能落到别的连接已经占用的区段上（界面看起来就像乱挑的）。
// 安装标识本身随机生成、落库保存、跨重启不变，正好当这个基准的种子。
//
// 取不到标识（极少数环境）时返回 0：退回按序号分配的老行为。
func (s *Service) defaultAddrOffset(ctx context.Context) int {
	id := strings.TrimSpace(s.installID(ctx))
	if id == "" {
		return 0
	}
	sum := sha256.Sum256([]byte(id))
	return int(binary.BigEndian.Uint16(sum[:2]) % addrSpan)
}
