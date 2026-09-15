package service

import (
	"context"
	"strings"

	"fnwg/internal/notify"
)

// NotifyStatus 返回通知配置与最近一次发送结果。
//
// 只返回脱敏后的地址：地址里通常带着访问令牌，
// 而这个接口只要求登录即可访问（只读角色也要能看到「通知有没有配好」）。
func (s *Service) NotifyStatus(ctx context.Context) notify.Status {
	return s.notifier.Status(ctx)
}

// SendTestNotify 立即发送一条测试通知，供用户确认地址是否可用。
func (s *Service) SendTestNotify(ctx context.Context, a Actor) (notify.Result, error) {
	res, err := s.notifier.SendTest(ctx)
	if err != nil {
		s.audit(ctx, a, "settings.notify_test", "settings", notify.SettingWebhook, "", "", "fail", err.Error())
		return res, err
	}
	result := "ok"
	if !res.OK {
		result = "fail"
	}
	// 测试发送会真实发起一次外网请求，属于可感知动作，必须留痕。
	s.audit(ctx, a, "settings.notify_test", "settings", notify.SettingWebhook, "", "", result, res.Message)
	return res, nil
}

// normalizeNotifySettings 归一化通知相关设置项，取值非法时直接拒绝保存。
//
// 这几个设置项直接决定「配了到底能不能收到消息」：地址写错、格式写错都表现为
// 「配完了但一直没动静」。在这里拒绝，好过让用户对着一个静默失效的开关反复检查。
func normalizeNotifySettings(kv map[string]string) error {
	if raw, ok := kv[notify.SettingWebhook]; ok {
		if strings.TrimSpace(raw) == "" {
			kv[notify.SettingWebhook] = ""
		} else if _, err := notify.ValidateURL(raw); err != nil {
			return err
		}
	}
	if raw, ok := kv[notify.SettingFormat]; ok {
		kv[notify.SettingFormat] = notify.NormalizeFormat(raw)
	}
	// 事件开关存的是「被明确关闭的事件」：丢掉不认识的名字，
	// 顺序与去重都归一化，保证同一个意图只有一种存储形态。
	if raw, ok := kv[notify.SettingEventsOff]; ok {
		kv[notify.SettingEventsOff] = notify.FormatDisabled(strings.Split(raw, ","))
	}
	// 兼容 0.7.0 客户端提交的「开启集」：换算成关闭集，不再写回旧键。
	// 旧值 "none" 表示当时全部关闭，换算后同样得到「全部关闭」。
	if raw, ok := kv[notify.SettingEventsLegacy]; ok {
		on := map[string]bool{}
		for _, k := range strings.Split(raw, ",") {
			on[strings.TrimSpace(k)] = true
		}
		off := []string{}
		for _, k := range notify.Kinds() {
			if !on[k.Kind] {
				off = append(off, k.Kind)
			}
		}
		delete(kv, notify.SettingEventsLegacy)
		kv[notify.SettingEventsOff] = notify.FormatDisabled(off)
	}
	return nil
}
