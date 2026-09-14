package service

import (
	"context"
	"fmt"
	"strings"

	"fnwg/internal/model"
)

func orEmptyStrings(list []string) []string {
	if list == nil {
		return []string{}
	}
	return list
}

func orEmptyRoutes(list []model.DefaultRoute) []model.DefaultRoute {
	if list == nil {
		return []model.DefaultRoute{}
	}
	return list
}

// NetworkCheckResult 是网络自检结果（面向用户的可读形式）。
type NetworkCheckResult struct {
	// Healthy 表示未发现任何影响 NAS 系统网络的问题。
	Healthy bool `json:"healthy"`
	// RouteInfoReadable 表示能否读取真实路由表（演示模式为 false）。
	RouteInfoReadable bool `json:"route_info_readable"`
	// ManagedInterfaces 本应用创建过的连接（网卡）。
	ManagedInterfaces []string `json:"managed_interfaces"`
	// SystemDefaults 系统自己的上网路线（应指向主网卡）。
	SystemDefaults []model.DefaultRoute `json:"system_defaults"`
	// StrayDefaults 本应用造成的异常上网路线（应被清除）。
	StrayDefaults []model.DefaultRoute `json:"stray_defaults"`
	// Messages 面向用户的结论说明。
	Messages []string `json:"messages"`
}

// CheckNetwork 执行只读自检，不修改任何设置。
func (s *Service) CheckNetwork(ctx context.Context) (*NetworkCheckResult, error) {
	rep, err := s.Core.InspectNetwork(ctx)
	if err != nil {
		return nil, err
	}
	// 统一把 nil 切片归一化为空数组，避免前端拿到 null
	res := &NetworkCheckResult{
		Healthy:           len(rep.StrayDefaults) == 0,
		ManagedInterfaces: orEmptyStrings(rep.ManagedInterfaces),
		SystemDefaults:    orEmptyRoutes(rep.Defaults),
		StrayDefaults:     orEmptyRoutes(rep.StrayDefaults),
	}
	res.RouteInfoReadable = rep.RouteInfoReadable
	if len(rep.ManagedInterfaces) == 0 {
		res.Messages = append(res.Messages, "本应用尚未创建任何连接，不会对系统网络产生任何影响。")
	} else {
		res.Messages = append(res.Messages,
			fmt.Sprintf("本应用创建了 %d 条连接（%s），这些连接不会修改 NAS 自身的上网路线。",
				len(rep.ManagedInterfaces), strings.Join(rep.ManagedInterfaces, "、")))
	}
	if len(rep.StrayDefaults) > 0 {
		for _, d := range rep.StrayDefaults {
			res.Messages = append(res.Messages, fmt.Sprintf(
				"发现异常：NAS 的默认上网路线被指向了 %s（由本应用早期版本造成）。请点击「立即修复」，修复后 FN Connect 等系统功能即可恢复。",
				d.Dev))
		}
	} else if rep.RouteInfoReadable && len(rep.Defaults) == 0 {
		res.Healthy = false
		res.Messages = append(res.Messages,
			"发现异常：NAS 当前没有任何可用的默认上网路线，请到系统「网络设置」中重新保存一次网卡配置。")
	} else if !rep.RouteInfoReadable {
		res.Messages = append(res.Messages,
			"当前运行在演示模式，无法读取 NAS 的真实上网路线；在 fnOS 上运行时会显示实际检查结果。")
	} else {
		for _, d := range rep.Defaults {
			gw := d.Gw
			if gw == "" {
				gw = "（无网关）"
			}
			res.Messages = append(res.Messages, fmt.Sprintf("NAS 上网路线正常：经由 %s（网关 %s）。", d.Dev, gw))
		}
	}
	return res, nil
}

// RepairNetwork 清除本应用造成的网络残留（不会影响系统自身的任何设置）。
func (s *Service) RepairNetwork(ctx context.Context, a Actor) ([]string, error) {
	actions, err := s.Core.RepairNetwork(ctx)
	if err != nil {
		s.audit(ctx, a, "net.repair", "system", "", "", "", "error", err.Error())
		return actions, err
	}
	s.audit(ctx, a, "net.repair", "system", "", "", fmt.Sprint(len(actions)), "ok", strings.Join(actions, "; "))
	_ = s.Store.AddLog(ctx, "warn", "netguard", "执行网络自检修复", strings.Join(actions, "; "))
	return actions, nil
}

// CleanupNetwork 删除本应用创建的全部内核对象（供「停用」与「卸载」使用）。
func (s *Service) CleanupNetwork(ctx context.Context, a Actor) ([]string, error) {
	actions, err := s.Core.CleanupNetwork(ctx)
	if err != nil {
		return actions, err
	}
	s.audit(ctx, a, "net.cleanup", "system", "", "", fmt.Sprint(len(actions)), "ok", strings.Join(actions, "; "))
	return actions, nil
}
