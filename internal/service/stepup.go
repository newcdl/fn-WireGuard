// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package service

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"fnwg/internal/model"
	"fnwg/internal/totp"
)

// SettingGatewayStepUp 是「敏感操作前再验证一次」的开关键。
//
// 默认**关**：从飞牛桌面点开就免密进来，是这套功能的意义所在；
// 要不要在此基础上再要一次动态口令，交给用户自己决定，默认不给谁加坎。
const SettingGatewayStepUp = "gateway_step_up"

// StepUpTTL 是「刚验证过」的有效期：这段时间内连着做敏感操作不必反复输码。
// 10 分钟是够做完一件事、又不至于让一次验证长时间有效的折中。
const StepUpTTL = 10 * time.Minute

// sensitivePerms 是需要步进验证的权限。
//
// 只挑三类：**泄露凭据**（查看本机密钥）、**覆盖数据**（用备份还原）、**改账号**（账号管理）。
// 挑多了会把功能变成打扰，挑少了等于没开。
var sensitivePerms = map[string]bool{
	model.PermKeyReveal:     true,
	model.PermBackupRestore: true,
	model.PermUserManage:    true,
}

// SensitivePerm 报告某个权限是否属于敏感操作。
func SensitivePerm(perm string) bool { return sensitivePerms[perm] }

// stepUpGrants 记「某个账号刚刚验证过」。
//
// 放在进程内存里：这只是一张 10 分钟的临时许可，进程重启后重新验一次不算负担，
// 而落库反而要额外处理过期清理与多实例一致性 —— 为一次临时许可不值得。
var (
	stepUpMu     sync.Mutex
	stepUpGrants = map[int64]time.Time{}
)

// stepUpClock 是取当前时间的入口，仅为测试能拨表验证「许可会过期」。
// 有效期写错（比如写成永久有效）是一次不显眼的越权，必须有办法验它。
var stepUpClock = time.Now

// StepUpEnabled 报告开关是否打开。
func (s *Service) StepUpEnabled(ctx context.Context) bool {
	kv, err := s.Store.AllSettings(ctx)
	if err != nil {
		// 读不到设置时**按关闭处理**：这是一道附加的门，
		// 配置读不出来时把它当成「开着」，会把所有人挡在敏感操作之外。
		return false
	}
	return kv[SettingGatewayStepUp] == "1"
}

// StepUpFresh 报告该账号是否在有效期内验证过。
func (s *Service) StepUpFresh(userID int64) bool {
	stepUpMu.Lock()
	defer stepUpMu.Unlock()
	at, ok := stepUpGrants[userID]
	if !ok || stepUpClock().Sub(at) > StepUpTTL {
		delete(stepUpGrants, userID)
		return false
	}
	return true
}

// MarkStepUpVerified 记录一次验证成功。
func (s *Service) MarkStepUpVerified(userID int64) {
	stepUpMu.Lock()
	defer stepUpMu.Unlock()
	stepUpGrants[userID] = time.Now()
}

// VerifyStepUp 用账号自己的动态口令完成一次步进验证。
//
// 飞牛身份账号**默认没有动态口令**（它们是凭飞牛身份进来的），
// 所以没绑定时给出的必须是「先去绑一次」这种能照做的指引，而不是一句「验证失败」。
func (s *Service) VerifyStepUp(ctx context.Context, u *model.User, code string) error {
	if u == nil {
		return errors.New("未登录")
	}
	code = strings.TrimSpace(code)
	if code == "" {
		return errors.New("请输入验证器 App 当前显示的 6 位数字")
	}
	if u.TOTPSecret == "" {
		return errors.New("这个账号还没有绑定动态口令，请先在「系统设置 → 账号安全」里绑定一次，再回来做这一步")
	}
	// skew=1：容忍前后一个时间窗，手机与服务端时钟略有偏差时不必反复重试。
	if !totp.Verify(u.TOTPSecret, code, time.Now(), 1) {
		return errors.New("验证码不正确")
	}
	s.MarkStepUpVerified(u.ID)
	return nil
}

// normalizeStepUpSetting 规范化这个开关的取值。
//
// 只认 "0"/"1"：其它写法（true/on/yes）一律拒收，避免出现
// 「界面上开着、服务端按关闭处理」这类两边说法不一致的状态。
func normalizeStepUpSetting(kv map[string]string) error {
	v, ok := kv[SettingGatewayStepUp]
	if !ok {
		return nil
	}
	switch v {
	case "0", "1":
		return nil
	default:
		return errors.New("敏感操作二次验证的取值只能是 0 或 1")
	}
}
