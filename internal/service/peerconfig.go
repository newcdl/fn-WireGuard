// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package service

import (
	"context"
	"fmt"
	"strings"

	"fnwg/internal/model"
	"fnwg/internal/wgback"
	"fnwg/internal/wgconf"
	"fnwg/internal/wgkey"
)

// 本文件负责两件事：
//
//  1. 判断「设备里那份配置」是否已经与当前设置不一致（配置已过期）；
//  2. 拒绝明显自相矛盾的「通行范围」写法。
//
// 核心事实：改通行范围、对外地址、DNS 只影响**之后新生成**的配置，
// 设备里已经导入的那份不会自动变。界面上必须把这件事说清楚，
// 否则用户会以为改完就生效了，然后对着「明明改了范围却还是访问不了」困惑很久。

// clientBaseline 是与单台设备无关的配置输入（按连接缓存，避免逐台设备重复探测）。
type clientBaseline struct {
	endpoint  string
	serverPub string
	dns       []string
	mtu       int
}

// baselineFor 计算一条连接的公共配置输入。
func (s *Service) baselineFor(ctx context.Context, it *model.Interface) (clientBaseline, error) {
	pub, err := wgkey.PublicKey(it.PrivateKey)
	if err != nil {
		return clientBaseline{}, err
	}
	endpoint, _ := s.serverEndpoint(ctx, it)
	return clientBaseline{endpoint: endpoint, serverPub: pub, dns: it.DNS, mtu: it.MTU}, nil
}

// peerConfigFingerprint 计算某台设备**当前应当**拿到的配置指纹。
//
// 刻意复用 clientAllowedIPs 与 SplitClientAndServerIPs：
// 指纹与实际渲染配置必须走同一套推导，否则会出现「配置没改却提示过期」
// 或反过来的假阴性 —— 后者更糟，用户会以为设备上那份还是最新的。
func (s *Service) peerConfigFingerprint(ctx context.Context, it *model.Interface, p *model.Peer, base clientBaseline) string {
	clientAddrs, extraRoutes := wgconf.SplitClientAndServerIPs(it, p)
	return wgconf.ClientFingerprint(wgconf.ClientConfigInputs{
		Endpoint:    base.endpoint,
		ClientAddrs: clientAddrs,
		AllowedIPs:  s.clientAllowedIPs(ctx, it, p, extraRoutes),
		DNS:         base.dns,
		MTU:         base.mtu,
		Keepalive:   p.Keepalive,
		ServerPub:   base.serverPub,
	})
}

// markConfigStale 标记设备列表里「配置已过期」的设备。
//
// 判定规则：
//   - 指纹为空 = 从未生成过配置（例如设备是用别人的识别码加进来的、或私钥没托管），
//     不标过期，界面对这种设备另有提示；
//   - 指纹不一致 = 设备里那份配置已经不是当前设置生成的了，需要重新扫码导入。
func (s *Service) markConfigStale(ctx context.Context, peers []model.Peer) {
	baselines := map[int64]clientBaseline{}
	ifaces := map[int64]*model.Interface{}
	for i := range peers {
		p := &peers[i]
		if p.ConfigFingerprint == "" {
			continue
		}
		it, ok := ifaces[p.InterfaceID]
		if !ok {
			loaded, err := s.Store.GetInterface(ctx, p.InterfaceID)
			if err != nil {
				continue
			}
			it = loaded
			ifaces[p.InterfaceID] = it
		}
		base, ok := baselines[it.ID]
		if !ok {
			b, err := s.baselineFor(ctx, it)
			if err != nil {
				continue
			}
			base = b
			baselines[it.ID] = base
		}
		p.ConfigStale = s.peerConfigFingerprint(ctx, it, p, base) != p.ConfigFingerprint
	}
}

// rememberPeerConfig 记录「这台设备刚刚拿到的配置」。
//
// 由 PeerConfig（生成配置/二维码）调用。在读取接口里写库略显意外，
// 但语义是准确的：我们确实刚刚把这份配置交付给了设备，
// 而这是判断「它什么时候会过期」的唯一依据。指纹没变时不产生写入。
func (s *Service) rememberPeerConfig(ctx context.Context, p *model.Peer, fingerprint string) {
	if fingerprint == "" || fingerprint == p.ConfigFingerprint {
		return
	}
	p.ConfigFingerprint = fingerprint
	if err := s.Store.UpdatePeer(ctx, p); err != nil {
		s.Log.Warn("记录设备配置指纹失败", "peer", p.ID, "err", err)
	}
}

// checkScopeConflicts 拒绝「通行范围」里明显自相矛盾的写法。
//
// 两类会被拒绝，都是「填了但结果一定不是用户想要」的情况：
//
//  1. 写了默认路由（0.0.0.0/0、::/0）：那是「全部流量」模式的语义。
//     混在自定义范围里会让设备把上网流量也一并塞进隧道，与用户以为的
//     「只多放行一个网段」完全不同 —— 直接让他改用「全部流量」模式；
//  2. 与**其它连接**的隧道网段重叠：包会被送进另一条隧道，
//     用户以为在访问这台 NAS，实际连到了另一处网络。
//
// 与本连接自己的隧道网段重叠是**允许**的：那正是「访问同隧道内的其它设备」。
func (s *Service) checkScopeConflicts(ctx context.Context, p *model.Peer) error {
	for _, cidr := range p.ClientAllowedIPs {
		if wgback.IsDefaultRouteCIDR(cidr) {
			return fmt.Errorf("「自定义可访问范围」里不要写 %s（这是全部流量的写法）："+
				"它会让设备的上网流量也全部走这里。如果你的本意就是「全部流量走连接」，"+
				"请把上面的「设备上网方式」改成「在外上网也走家里」", strings.TrimSpace(cidr))
		}
	}
	others, err := s.otherInterfaces(ctx, p.InterfaceID)
	if err != nil {
		// 读不到其它连接时放行：这是校验，不是安全红线，
		// 让配置先存下去，收敛期的冲突诊断会把问题说出来。
		return nil
	}
	for _, other := range others {
		if !other.Enabled {
			continue
		}
		for _, cidr := range p.ClientAllowedIPs {
			if addrOverlapsAny([]model.Interface{other}, cidr) {
				return fmt.Errorf("「自定义可访问范围」里的 %s 与连接「%s」的专用地址重叠："+
					"设备发往该网段的流量会被送进那条连接，而不是当前这条。"+
					"请换一个不冲突的网段，或把这台设备放到「%s」下", strings.TrimSpace(cidr), other.Name, other.Name)
			}
		}
	}
	return nil
}
