// Package totp 实现 RFC 6238 基于时间的一次性口令（TOTP），供登录二次验证使用。
//
// 为什么自己实现而不是引入库：与 internal/dnsserver 自实现极简解析器同一条理由 ——
// 本项目刻意不为一个只用到几步标准库调用的能力引入外部依赖（那会让二进制变大、
// 增加供应链面）。TOTP 本体只有「HMAC-SHA1 + 动态截断」两步，
// 并且 RFC 6238 附录 B 提供了官方测试向量，可以逐条断言正确性。
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// Period 是口令的有效期，RFC 6238 推荐 30 秒。
	Period = 30
	// Digits 是口令位数。6 位是各家身份验证器（Google/Microsoft Authenticator、
	// 1Password、Authy）的通用默认值。
	Digits = 6
	// SecretBytes 是密钥长度：RFC 4226 要求至少 128 位，推荐 160 位（等于 SHA-1 输出长度）。
	SecretBytes = 20
	// CodeMod 是口令取模基数。
	codeMod = 1_000_000
)

// b32 是 TOTP 密钥的编码方式：RFC 4648 标准 Base32、无 padding。
// 身份验证器普遍接受无 padding 形式，而 urlsafe 变体反而不被少数客户端识别。
var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateSecret 生成一个新的随机密钥（Base32 编码，可直接放进 otpauth:// 链接）。
func GenerateSecret() (string, error) {
	buf := make([]byte, SecretBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return b32.EncodeToString(buf), nil
}

// NormalizeSecret 规整密钥写法：去空格与连字符、统一大写、去掉 padding。
// 用户手动输入密钥时经常带上分组用的空格或小写字母，不规整就会解不出来。
func NormalizeSecret(secret string) string {
	s := strings.ToUpper(secret)
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "-", "")
	return strings.TrimRight(s, "=")
}

// decodeSecret 把 Base32 密钥解成字节。
func decodeSecret(secret string) ([]byte, error) {
	key, err := b32.DecodeString(NormalizeSecret(secret))
	if err != nil {
		return nil, fmt.Errorf("密钥不是合法的 Base32 编码: %w", err)
	}
	if len(key) == 0 {
		return nil, fmt.Errorf("密钥为空")
	}
	return key, nil
}

// Code 计算密钥在 t 时刻的口令。
func Code(secret string, t time.Time) (string, error) {
	key, err := decodeSecret(secret)
	if err != nil {
		return "", err
	}
	return codeAt(key, counterAt(t)), nil
}

// Verify 校验口令是否有效。
//
// skew 是允许的时间步漂移（0 表示只接受当前步）：客户端时钟与 NAS 常有几秒到
// 十几秒的偏差，skew=1 即多接受前后各一个 30 秒窗口，是业界通行做法。
func Verify(secret, pass string, t time.Time, skew int) bool {
	pass = strings.TrimSpace(pass)
	if len(pass) != Digits {
		return false
	}
	key, err := decodeSecret(secret)
	if err != nil {
		return false
	}
	cur := int64(counterAt(t))
	for i := -skew; i <= skew; i++ {
		c := cur + int64(i)
		if c < 0 {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(codeAt(key, uint64(c))), []byte(pass)) == 1 {
			return true
		}
	}
	return false
}

// counterAt 返回 t 对应的时间步。
func counterAt(t time.Time) uint64 {
	return uint64(t.Unix() / Period)
}

// codeAt 按 RFC 4226 §5.3 计算指定时间步的口令。
func codeAt(key []byte, counter uint64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)

	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)

	// 动态截断：取最后一字节低 4 位作为偏移，从该处取 4 字节并抹掉最高位，
	// 保证结果恒为正数且与平台字节序无关。
	off := sum[len(sum)-1] & 0x0f
	v := uint32(sum[off]&0x7f)<<24 |
		uint32(sum[off+1])<<16 |
		uint32(sum[off+2])<<8 |
		uint32(sum[off+3])
	return fmt.Sprintf("%0*d", Digits, v%codeMod)
}

// ProvisioningURI 生成供身份验证器扫码的 otpauth:// 链接。
//
// account 一般是「用户名@NAS」，issuer 是显示在验证器里的服务名。
func ProvisioningURI(issuer, account, secret string) string {
	v := url.Values{}
	v.Set("secret", NormalizeSecret(secret))
	v.Set("issuer", issuer)
	v.Set("algorithm", "SHA1")
	v.Set("digits", strconv.Itoa(Digits))
	v.Set("period", strconv.Itoa(Period))
	// label 里的冒号是 otpauth 约定的「发行方:账号」分隔符，需保留；
	// url.PathEscape 不会转义冒号，正好符合要求。
	return "otpauth://totp/" + url.PathEscape(issuer+":"+account) + "?" + v.Encode()
}

// ---------------------------------------------------------------- 恢复码

const (
	// recoveryAlphabet 刻意剔除了 0/O、1/I/L 等易混字符：恢复码是要用户
	// 手抄到纸上或密码管理器里的，抄错一个字符就等于失效。
	recoveryAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
	// RecoveryCodeChars 是单个恢复码的字符数。31^10 ≈ 8×10^14（约 50 位熵），
	// 配合登录失败限流足够抵抗在线猜测。
	RecoveryCodeChars = 10
	// RecoveryCodeCount 是每次开启二次验证时生成的恢复码数量。
	RecoveryCodeCount = 10
	// recoveryGroup 是展示分组长度：XXXXX-XXXXX 比连写更好抄。
	recoveryGroup = 5
)

// GenerateRecoveryCodes 生成一组一次性恢复码（明文，仅在开启时展示一次）。
//
// 落库前由调用方做哈希，这里只负责生成与规整，不接触存储。
func GenerateRecoveryCodes(n int) ([]string, error) {
	if n <= 0 {
		n = RecoveryCodeCount
	}
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		c, err := randomRecoveryCode()
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// randomRecoveryCode 生成单个形如 XXXXX-XXXXX 的恢复码。
func randomRecoveryCode() (string, error) {
	buf := make([]byte, RecoveryCodeChars)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	var sb strings.Builder
	for i, b := range buf {
		// 取模会带来极轻微的偏斜（256 不是 31 的整数倍），
		// 对 50 位熵的恢复码而言不构成实际影响。
		if i > 0 && i%recoveryGroup == 0 {
			sb.WriteByte('-')
		}
		sb.WriteByte(recoveryAlphabet[int(b)%len(recoveryAlphabet)])
	}
	return sb.String(), nil
}

// NormalizeRecoveryCode 规整用户输入的恢复码：大小写、连字符、空格一律忽略，
// 使「抄写时加了空格」或「用小写输入」都能通过校验。
func NormalizeRecoveryCode(code string) string {
	s := strings.ToUpper(code)
	s = strings.ReplaceAll(s, "-", "")
	s = strings.ReplaceAll(s, " ", "")
	return s
}
