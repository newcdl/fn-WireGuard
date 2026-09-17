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
	// trustedDeviceTTL 是「信任本设备」的有效期。
	//
	// 30 天是常见的折中点：太短则「信任」形同虚设、每次都要掏手机；
	// 太长则一台被入侵或转手的设备会长期持有一张免二次验证的通行证。
	trustedDeviceTTL = 30 * 24 * time.Hour
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
//
// trustDevice 为真时（用户在界面上勾选了「信任本设备」）额外签发一枚设备令牌，
// 该设备在 30 天内登录可跳过这一步。
func (s *Service) CompleteTOTPLogin(ctx context.Context, challenge, code string, trustDevice bool, ua, ip string) (*LoginStep, error) {
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
	step, err := s.issueSession(ctx, u, ua, ip)
	if err != nil {
		return nil, err
	}
	if trustDevice {
		token, expiresAt, err := s.trustDevice(ctx, u, ua, ip)
		if err != nil {
			// 登记受信任设备失败不应让整次登录失败——会话已经签发，
			// 用户下次多输一次验证码即可，比把他挡在门外合理。
			_ = s.Store.AddLog(ctx, "warn", "auth", "记录受信任设备失败，本次登录不受影响", err.Error())
		} else {
			step.DeviceToken = token
			step.DeviceExpiresAt = expiresAt
		}
	}
	return step, nil
}

// trustDevice 为账号登记一台受信任设备，返回明文令牌（仅此一次）与过期时间。
func (s *Service) trustDevice(ctx context.Context, u *model.User, ua, ip string) (string, time.Time, error) {
	token := newToken(32)
	d := &model.TrustedDevice{
		UserID:    u.ID,
		TokenHash: hashToken(token),
		Name:      deviceName(ua),
		SrcIP:     ip,
		ExpiresAt: time.Now().Add(trustedDeviceTTL),
	}
	if err := s.Store.CreateTrustedDevice(ctx, d); err != nil {
		return "", time.Time{}, err
	}
	s.audit(ctx, Actor{UserID: u.ID, Username: u.Username, SrcIP: ip}, "totp.trust_device", "user",
		fmt.Sprint(u.ID), "", d.Name, "ok", "")
	return token, d.ExpiresAt, nil
}

// deviceName 从 User-Agent 里提取一个便于人识别的设备名，例如「Chrome · macOS」。
//
// 不引入 UA 解析库：这里的目的只是让用户能在受信任设备列表里认出哪台是自己，
// 一个粗糙但稳定的启发式足够，解析不出来时退回原文截断，绝不返回空串。
// 注意判定顺序——Edge 的 UA 里含 "Chrome/"、Chrome 的含 "Safari/"，先判前者才准。
func deviceName(ua string) string {
	ua = strings.TrimSpace(ua)
	if ua == "" {
		return "未知设备"
	}
	osName := ""
	switch {
	case strings.Contains(ua, "Windows"):
		osName = "Windows"
	case strings.Contains(ua, "iPhone"):
		osName = "iPhone"
	case strings.Contains(ua, "iPad"):
		osName = "iPad"
	case strings.Contains(ua, "Android"):
		osName = "Android"
	case strings.Contains(ua, "Mac OS X"), strings.Contains(ua, "Macintosh"):
		osName = "macOS"
	case strings.Contains(ua, "Linux"):
		osName = "Linux"
	}
	browser := ""
	switch {
	case strings.Contains(ua, "Edg/"):
		browser = "Edge"
	case strings.Contains(ua, "OPR/"), strings.Contains(ua, "Opera"):
		browser = "Opera"
	case strings.Contains(ua, "Chrome/"):
		browser = "Chrome"
	case strings.Contains(ua, "Firefox/"):
		browser = "Firefox"
	case strings.Contains(ua, "Safari/"):
		browser = "Safari"
	}
	switch {
	case browser != "" && osName != "":
		return browser + " · " + osName
	case browser != "":
		return browser
	case osName != "":
		return osName
	}
	r := []rune(ua)
	if len(r) > 40 {
		return string(r[:40]) + "…"
	}
	return ua
}

// ListTrustedDevices 返回某账号的受信任设备列表。
func (s *Service) ListTrustedDevices(ctx context.Context, userID int64) ([]model.TrustedDevice, error) {
	return s.Store.ListTrustedDevices(ctx, userID)
}

// RevokeTrustedDevice 撤销一台受信任设备（只能撤销自己的）。
func (s *Service) RevokeTrustedDevice(ctx context.Context, userID, id int64, a Actor) error {
	if err := s.Store.DeleteTrustedDevice(ctx, userID, id); err != nil {
		return errors.New("设备不存在或不属于当前账号")
	}
	s.audit(ctx, a, "totp.revoke_device", "user", fmt.Sprint(userID), "", fmt.Sprint(id), "ok", "")
	return nil
}

// RevokeAllTrustedDevices 撤销某账号的全部受信任设备。
func (s *Service) RevokeAllTrustedDevices(ctx context.Context, userID int64, a Actor) error {
	if err := s.Store.DeleteAllTrustedDevices(ctx, userID); err != nil {
		return err
	}
	s.audit(ctx, a, "totp.revoke_device", "user", fmt.Sprint(userID), "", "全部设备", "ok", "")
	return nil
}

// ResetUserTOTP 由管理员重置某个账号的二次验证（清空密钥、恢复码与受信任设备）。
//
// 这是「用户把自己锁在门外」时的正规救法，官方 2FA 同样提供该能力。
// 没有它，用户只能靠恢复码；恢复码也丢了就只能去改数据库。
func (s *Service) ResetUserTOTP(ctx context.Context, userID int64, a Actor) error {
	u, err := s.Store.GetUser(ctx, userID)
	if err != nil {
		return err
	}
	// 飞牛账号在本应用里不该有绑定：开启入口本身就拒绝（见 gatewayTOTPRefusal）。
	// 这里一并挡掉，是为了让「界面不显示」与「接口不接受」两处语义一致，
	// 而不是留一个只在 UI 上隐藏、直连接口仍能生效的后门。
	if s.IsGatewayUser(ctx, userID) {
		s.audit(ctx, a, "totp.admin_reset", "user", fmt.Sprint(userID), u.Username, "", "deny", "飞牛账号的二次验证由飞牛管理")
		return errors.New(gatewayTOTPRefusal)
	}
	if u.TOTPSecret == "" {
		return errors.New("该账号未开启二次验证")
	}
	if err := s.Store.ClearUserTOTP(ctx, userID); err != nil {
		return err
	}
	// 重置后该账号只剩口令一道防线，把在线会话一并收掉，
	// 避免「重置前就已经登录着的会话」继续被使用。
	_ = s.Store.DeleteUserSessions(ctx, userID)
	s.audit(ctx, a, "totp.admin_reset", "user", fmt.Sprint(userID), u.Username, "", "ok", "管理员重置了二次验证")
	return nil
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
	return s.newTOTPSetup(u)
}

// newTOTPSetup 生成一份绑定信息（不落库、尚未生效）。
//
// 与「谁在操作」无关，因此自助路径与管理员代开路径共用：
// 两者的差别只在进来之前要不要校验本人密码，绑定信息本身完全一样。
func (s *Service) newTOTPSetup(u *model.User) (*TOTPSetup, error) {
	secret, err := totp.GenerateSecret()
	if err != nil {
		return nil, err
	}
	return &TOTPSetup{
		Secret: secret,
		URI:    totp.ProvisioningURI(totpIssuer, u.Username, secret),
	}, nil
}

// AdminBeginTOTPSetup 由管理员为指定账号生成绑定信息（尚未生效）。
//
// 与自助路径只差一处：不校验「本人密码」—— 操作者本来就不是账号主人，
// 权限由调用方要求的 user.manage 保证。正因为它少了那道校验，才必须在入口
// 挡住飞牛账号（见 gatewayTOTPRefusal）：那条路上二次验证不可能生效，
// 允许绑定等于让管理员以为自己加固了这个账号，实际上什么也没发生。
func (s *Service) AdminBeginTOTPSetup(ctx context.Context, userID int64, a Actor) (*TOTPSetup, error) {
	u, err := s.Store.GetUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	if s.IsGatewayUser(ctx, userID) {
		s.audit(ctx, a, "totp.admin_setup", "user", fmt.Sprint(userID), u.Username, "", "deny", "飞牛账号的二次验证由飞牛管理")
		return nil, errors.New(gatewayTOTPRefusal)
	}
	s.audit(ctx, a, "totp.admin_setup", "user", fmt.Sprint(userID), u.Username, "", "ok", "管理员发起了二次验证绑定")
	return s.newTOTPSetup(u)
}

// AdminEnableTOTP 由管理员用一次动态口令确认绑定并开启，返回一次性恢复码。
//
// 恢复码明文同样只返回一次，由管理员交回账号主人保存。
func (s *Service) AdminEnableTOTP(ctx context.Context, userID int64, secret, code string, a Actor) ([]string, error) {
	u, err := s.Store.GetUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	if s.IsGatewayUser(ctx, userID) {
		s.audit(ctx, a, "totp.admin_enable", "user", fmt.Sprint(userID), u.Username, "", "deny", "飞牛账号的二次验证由飞牛管理")
		return nil, errors.New(gatewayTOTPRefusal)
	}
	return s.enableTOTPWith(ctx, u, secret, code, a)
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
	return s.enableTOTPWith(ctx, u, secret, code, a)
}

// enableTOTPWith 是启用二次验证的公共实现（自助与管理员代开共用）。
func (s *Service) enableTOTPWith(ctx context.Context, u *model.User, secret, code string, a Actor) ([]string, error) {
	userID := u.ID
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
