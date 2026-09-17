package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"fnwg/internal/model"
	"fnwg/internal/totp"
)

const (
	// totpChallengeTTL 是「口令已通过、等动态口令」这一步的有效期。
	// 故意很短：挑战本身等价于半个登录凭据，泄露它等于省掉攻击者一步。
	totpChallengeTTL = 5 * time.Minute
	// totpMaxAttempts 是单个挑战允许的失败次数，超过即作废，必须重新输密码。
	// 动态口令只有 6 位，没有这个上限就等于允许在线爆破 100 万种可能。
	totpMaxAttempts = 5
	// totpSkew 允许的时间步漂移（±1 步 = ±30 秒），容纳手机与 NAS 的时钟误差。
	totpSkew = 1
	// totpIssuer 是显示在验证器 App 里的服务名。
	totpIssuer = "WireGuard 管理工具"
)

// TOTPSetup 是开启二次验证前的绑定信息（密钥 + 扫码链接）。
type TOTPSetup struct {
	Secret string `json:"secret"`
	URI    string `json:"uri"`
}

// TOTPStatus 是二次验证的当前状态。
type TOTPStatus struct {
	Enabled           bool `json:"enabled"`
	RecoveryRemaining int  `json:"recovery_remaining"`
}

// CompleteTOTPLogin 提交动态口令（或一枚恢复码）完成二次验证登录。
func (s *Service) CompleteTOTPLogin(ctx context.Context, challenge, code, ua, ip string) (*LoginStep, error) {
	ch := strings.TrimSpace(challenge)
	if ch == "" {
		return nil, errors.New("登录状态已失效，请重新登录")
	}
	th := hashToken(ch)
	rec, err := s.Store.GetTOTPChallenge(ctx, th)
	if err != nil {
		// 不区分「不存在」与「已过期」：对外都是同一件事——重新登录。
		return nil, errors.New("验证已超时或失效，请重新登录")
	}
	u, err := s.Store.GetUser(ctx, rec.UserID)
	if err != nil || u.Status != 1 {
		_ = s.Store.DeleteTOTPChallenge(ctx, th)
		return nil, errors.New("账号不可用")
	}
	if !s.consumeTOTPOrRecovery(ctx, u, code) {
		n, _ := s.Store.BumpTOTPChallengeAttempts(ctx, th)
		if n >= totpMaxAttempts {
			_ = s.Store.DeleteTOTPChallenge(ctx, th)
			s.audit(ctx, Actor{UserID: u.ID, Username: u.Username, SrcIP: ip}, "auth.login.totp", "user",
				fmt.Sprint(u.ID), "", "", "deny", "动态口令连续错误，登录挑战已作废")
			return nil, errors.New("验证码错误次数过多，请重新输入密码登录")
		}
		s.audit(ctx, Actor{UserID: u.ID, Username: u.Username, SrcIP: ip}, "auth.login.totp", "user",
			fmt.Sprint(u.ID), "", "", "deny", "动态口令错误")
		return nil, errors.New("验证码不正确，请重试")
	}
	// 挑战一次性：成功了立刻删掉，防止同一个挑战换出两个会话。
	_ = s.Store.DeleteTOTPChallenge(ctx, th)
	return s.issueSession(ctx, u, ua, ip)
}

// TOTPChallengeUser 反查登录挑战对应的账号名。
//
// 只用于把二次验证的失败次数归到「IP+账号」这个限流键上：挑战本身是随机令牌，
// 限流器光看令牌不知道它属于谁，而归到「IP+账号」才能与密码那一步共用一套计数。
func (s *Service) TOTPChallengeUser(ctx context.Context, challenge string) (string, bool) {
	ch := strings.TrimSpace(challenge)
	if ch == "" {
		return "", false
	}
	rec, err := s.Store.GetTOTPChallenge(ctx, hashToken(ch))
	if err != nil {
		return "", false
	}
	u, err := s.Store.GetUser(ctx, rec.UserID)
	if err != nil {
		return "", false
	}
	return u.Username, true
}

// consumeTOTPOrRecovery 依次尝试「动态口令」与「恢复码」，命中恢复码时将其标记为已用。
//
// 先试动态口令是有意为之：它是日常路径（6 位数字，判断极快）；
// 恢复码要用 argon2id 逐个比对，开销大得多，只在动态口令不匹配时才走。
func (s *Service) consumeTOTPOrRecovery(ctx context.Context, u *model.User, code string) bool {
	code = strings.TrimSpace(code)
	if code == "" {
		return false
	}
	if u.TOTPSecret != "" && totp.Verify(u.TOTPSecret, code, time.Now(), totpSkew) {
		return true
	}
	// 恢复码：规整（去连字符/空格、转大写）后长度必然等于 RecoveryCodeChars，
	// 用长度先挡一道，避免把 6 位动态口令拿去跑 10 次 argon2id。
	norm := totp.NormalizeRecoveryCode(code)
	if len(norm) != totp.RecoveryCodeChars {
		return false
	}
	list, err := s.Store.ListUnusedRecoveryCodes(ctx, u.ID)
	if err != nil {
		return false
	}
	for _, rc := range list {
		if VerifyPassword(norm, rc.CodeHash) {
			_ = s.Store.MarkRecoveryCodeUsed(ctx, rc.ID)
			return true
		}
	}
	return false
}

// BeginTOTPSetup 生成一份新的绑定信息（此时**尚未落库**，也就尚未生效）。
//
// 要求验证当前口令：否则一个被盗用的会话就能把攻击者自己的验证器绑上来，
// 从而把真正的所有者永久锁在门外。
func (s *Service) BeginTOTPSetup(ctx context.Context, userID int64, password string, a Actor) (*TOTPSetup, error) {
	u, err := s.Store.GetUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	if !VerifyPassword(password, u.PasswordHash) {
		s.audit(ctx, a, "totp.setup", "user", fmt.Sprint(userID), "", "", "deny", "口令错误")
		return nil, errors.New("当前密码不正确")
	}
	secret, err := totp.GenerateSecret()
	if err != nil {
		return nil, err
	}
	return &TOTPSetup{
		Secret: secret,
		URI:    totp.ProvisioningURI(totpIssuer, u.Username, secret),
	}, nil
}

// EnableTOTP 用一次有效的动态口令确认绑定，正式开启二次验证，并返回一次性恢复码。
//
// 恢复码明文只在这里返回一次：落库的是 argon2id 哈希（与登录口令同一套算法），
// 之后任何人都无法再取回明文，包括管理员与备份文件。
func (s *Service) EnableTOTP(ctx context.Context, userID int64, password, secret, code string, a Actor) ([]string, error) {
	u, err := s.Store.GetUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	if !VerifyPassword(password, u.PasswordHash) {
		s.audit(ctx, a, "totp.enable", "user", fmt.Sprint(userID), "", "", "deny", "口令错误")
		return nil, errors.New("当前密码不正确")
	}
	secret = totp.NormalizeSecret(secret)
	if secret == "" {
		return nil, errors.New("缺少绑定密钥，请重新扫码")
	}
	// 必须用动态口令证明「验证器确实绑好了」：否则密钥一旦抄错，
	// 用户会在下次登录时被自己锁在门外，而且那时已经无法自救。
	if !totp.Verify(secret, code, time.Now(), totpSkew) {
		s.audit(ctx, a, "totp.enable", "user", fmt.Sprint(userID), "", "", "deny", "动态口令校验失败")
		return nil, errors.New("验证码不正确，请确认验证器里当前显示的 6 位数字")
	}
	codes, err := totp.GenerateRecoveryCodes(totp.RecoveryCodeCount)
	if err != nil {
		return nil, err
	}
	hashes := make([]string, 0, len(codes))
	for _, c := range codes {
		h, err := HashPassword(totp.NormalizeRecoveryCode(c))
		if err != nil {
			return nil, err
		}
		hashes = append(hashes, h)
	}
	if err := s.Store.SetUserTOTPSecret(ctx, userID, secret); err != nil {
		return nil, err
	}
	if err := s.Store.ReplaceRecoveryCodes(ctx, userID, hashes); err != nil {
		return nil, err
	}
	s.audit(ctx, a, "totp.enable", "user", fmt.Sprint(userID), "", fmt.Sprintf("%d 个恢复码", len(codes)), "ok", "")
	return codes, nil
}

// DisableTOTP 关闭二次验证。
//
// 除当前口令外还要求一次动态口令或恢复码：关闭二次验证是「降低安全」的操作，
// 只靠口令的话，口令一旦泄露，攻击者可以顺手把二次验证也关掉，
// 用户此前的防御就完全白费。
func (s *Service) DisableTOTP(ctx context.Context, userID int64, password, code string, a Actor) error {
	u, err := s.Store.GetUser(ctx, userID)
	if err != nil {
		return err
	}
	if u.TOTPSecret == "" {
		return errors.New("该账号未开启二次验证")
	}
	if !VerifyPassword(password, u.PasswordHash) {
		s.audit(ctx, a, "totp.disable", "user", fmt.Sprint(userID), "", "", "deny", "口令错误")
		return errors.New("当前密码不正确")
	}
	if !s.consumeTOTPOrRecovery(ctx, u, code) {
		s.audit(ctx, a, "totp.disable", "user", fmt.Sprint(userID), "", "", "deny", "动态口令校验失败")
		return errors.New("验证码不正确，请输入验证器当前显示的 6 位数字，或一枚恢复码")
	}
	if err := s.Store.ClearUserTOTP(ctx, userID); err != nil {
		return err
	}
	s.audit(ctx, a, "totp.disable", "user", fmt.Sprint(userID), "", "", "ok", "")
	return nil
}

// TOTPStatusOf 返回账号的二次验证状态与剩余恢复码数量。
func (s *Service) TOTPStatusOf(ctx context.Context, userID int64) (*TOTPStatus, error) {
	u, err := s.Store.GetUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	st := &TOTPStatus{Enabled: u.TOTPSecret != ""}
	if st.Enabled {
		n, err := s.Store.CountUnusedRecoveryCodes(ctx, userID)
		if err != nil {
			return nil, err
		}
		st.RecoveryRemaining = n
	}
	return st, nil
}
