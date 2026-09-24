// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"

	"fnwg/internal/model"
)

// 设备类型：让用户明确指定「这台机器是什么」，拓扑图上的图标就不再靠名字猜。
//
// 为什么不加在 DNS 记录表里：那要动库表与迁移；这里按 IP 存成一份设置
// （与巡检报告、入口状态同一套做法），升级与回滚都没有数据风险。
// 按 IP 而不是按记录 id：同一台设备将来改名字、重新登记，类型仍然跟着地址走。

const SettingDeviceKinds = "device_kinds"

// DeviceKindOption 是一个可选的设备类型（存英文值，界面显示中文）。
type DeviceKindOption struct {
	Value string `json:"value"`
	Label string `json:"label"`
}

// DeviceKindOptions 是可配置的类型清单，与拓扑图的图标一一对应：
// 配了就按它画，没配才按名字猜 —— 猜是兜底，用户说了算才是准的。
var DeviceKindOptions = []DeviceKindOption{
	{Value: "router", Label: "路由器 / 无线"},
	{Value: "switch", Label: "交换机"},
	{Value: "server", Label: "NAS / 服务器"},
	{Value: "computer", Label: "电脑"},
	{Value: "phone", Label: "手机 / 平板"},
	{Value: "printer", Label: "打印机"},
	{Value: "tv", Label: "电视 / 盒子"},
	{Value: "camera", Label: "摄像头"},
	{Value: "speaker", Label: "音箱"},
	{Value: "other", Label: "其它设备"},
}

// DeviceKindLabel 把类型值翻成中文；未知值原样返回（界面上不会出现空标签）。
func DeviceKindLabel(v string) string {
	for _, o := range DeviceKindOptions {
		if o.Value == v {
			return o.Label
		}
	}
	return v
}

func validDeviceKind(v string) bool {
	for _, o := range DeviceKindOptions {
		if o.Value == v {
			return true
		}
	}
	return false
}

// DeviceKinds 读取全部「IP → 类型」；没配过或内容坏了都返回空表。
//
// 坏掉时退回空表：类型只影响图标，不该让整张拓扑图读不出来。
func (s *Service) DeviceKinds(ctx context.Context) map[string]string {
	out := map[string]string{}
	raw := strings.TrimSpace(s.Store.GetSetting(ctx, SettingDeviceKinds, ""))
	if raw == "" {
		return out
	}
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return map[string]string{}
	}
	return out
}

// DeviceKindList 返回已配置的清单（按 IP 排序），供界面显示。
func (s *Service) DeviceKindList(ctx context.Context) []map[string]string {
	m := s.DeviceKinds(ctx)
	ips := make([]string, 0, len(m))
	for ip := range m {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	out := make([]map[string]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, map[string]string{"ip": ip, "kind": m[ip], "label": DeviceKindLabel(m[ip])})
	}
	return out
}

// SetDeviceKind 设置某台内网设备的类型；kind 传空表示清除（回到按名字自动判断）。
func (s *Service) SetDeviceKind(ctx context.Context, a Actor, ip, kind string) error {
	ip = strings.TrimSpace(ip)
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("IP 地址格式不对：%s", ip)
	}
	kind = strings.TrimSpace(kind)
	if kind != "" && !validDeviceKind(kind) {
		return fmt.Errorf("不认识的设备类型：%s", kind)
	}
	m := s.DeviceKinds(ctx)
	if kind == "" {
		delete(m, ip)
	} else {
		m[ip] = kind
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if err := s.Store.SetSetting(ctx, SettingDeviceKinds, string(raw)); err != nil {
		return err
	}
	what := "清除设备类型"
	if kind != "" {
		what = "记设备类型：" + DeviceKindLabel(kind)
	}
	return s.Store.AddAudit(ctx, &model.AuditEntry{
		UserID:     a.UserID,
		Username:   a.Username,
		SrcIP:      a.SrcIP,
		Action:     "devicekind.set",
		TargetType: "dns",
		TargetID:   ip,
		Result:     "ok",
		Message:    what,
	})
}
