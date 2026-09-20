// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package totp

import (
	"net/url"
	"strings"
	"testing"
	"time"
)

// rfcSecret 是 RFC 6238 附录 B 使用的密钥：ASCII 字符串 "12345678901234567890"
// 的 Base32 编码（SHA-1 用例）。
const rfcSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

// TestRFC6238Vectors 用 RFC 6238 附录 B 的官方测试向量逐条验证。
//
// 官方向量是 8 位口令，而本项目用业界通用的 6 位（Digits=6）。二者关系是
// 「动态截断得到同一个 31 位整数」，只是最后取模的基数不同（10^8 vs 10^6），
// 因此 6 位口令必然等于官方向量的后 6 位。
func TestRFC6238Vectors(t *testing.T) {
	cases := []struct {
		unix int64
		want string // RFC 官方的 8 位口令
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	}
	for _, c := range cases {
		got, err := Code(rfcSecret, time.Unix(c.unix, 0).UTC())
		if err != nil {
			t.Fatalf("Code(%d) 出错: %v", c.unix, err)
		}
		want := c.want[len(c.want)-Digits:]
		if got != want {
			t.Errorf("Code(%d) = %s，期望 %s（RFC 向量 %s 的后 %d 位）", c.unix, got, want, c.want, Digits)
		}
	}
}

func TestCodeIsStableWithinPeriod(t *testing.T) {
	// 同一个 30 秒窗口内，任意时刻算出的口令必须相同；跨窗口必须变化。
	// 1111111080 是 30 的整数倍（37037036×30），用它作基准才能保证
	// 「+29 秒仍在同一步、+30 秒跨到下一步」这两个断言成立。
	base := time.Unix(1111111080, 0).UTC()
	first, err := Code(rfcSecret, base)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := Code(rfcSecret, base.Add(29*time.Second)); got != first {
		t.Errorf("同一时间步内口令不应变化: %s != %s", got, first)
	}
	if got, _ := Code(rfcSecret, base.Add(30*time.Second)); got == first {
		t.Errorf("跨时间步后口令应当变化，但仍然得到 %s", got)
	}
}

func TestVerifySkew(t *testing.T) {
	now := time.Unix(1111111109, 0).UTC()
	prev, _ := Code(rfcSecret, now.Add(-Period*time.Second))
	next, _ := Code(rfcSecret, now.Add(Period*time.Second))
	cur, _ := Code(rfcSecret, now)

	// skew=1：前后各一个窗口都接受
	if !Verify(rfcSecret, cur, now, 1) {
		t.Error("当前口令应通过")
	}
	if !Verify(rfcSecret, prev, now, 1) {
		t.Error("上一个时间步的口令应通过（skew=1）")
	}
	if !Verify(rfcSecret, next, now, 1) {
		t.Error("下一个时间步的口令应通过（skew=1）")
	}
	// skew=0：只接受当前窗口
	if Verify(rfcSecret, prev, now, 0) {
		t.Error("skew=0 时上一个时间步的口令不应通过")
	}
	// 超出漂移范围必须拒绝
	far, _ := Code(rfcSecret, now.Add(5*Period*time.Second))
	if Verify(rfcSecret, far, now, 1) {
		t.Error("超出漂移范围的口令不应通过")
	}
}

func TestVerifyRejectsMalformed(t *testing.T) {
	now := time.Unix(1111111109, 0).UTC()
	for _, bad := range []string{"", "12345", "1234567", "abcdef", "  "} {
		if Verify(rfcSecret, bad, now, 1) {
			t.Errorf("非法口令 %q 不应通过", bad)
		}
	}
	// 密钥非法时一律拒绝，而不是 panic
	if Verify("not-base32-!!!", "123456", now, 1) {
		t.Error("密钥非法时应拒绝")
	}
}

func TestGenerateSecretAndURI(t *testing.T) {
	s, err := GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	if len(NormalizeSecret(s)) != 32 { // 20 字节 → 32 个 Base32 字符
		t.Fatalf("密钥长度异常: %q（%d 字符）", s, len(NormalizeSecret(s)))
	}
	// 生成的密钥必须能被自己使用（可解出、能算出口令）
	if _, err := Code(s, time.Now()); err != nil {
		t.Fatalf("自己生成的密钥应当可用: %v", err)
	}
	// 两次生成不应重复
	s2, _ := GenerateSecret()
	if s == s2 {
		t.Error("两次生成的密钥不应相同")
	}

	uri := ProvisioningURI("WireGuard 管理工具", "admin@nas", s)
	for _, want := range []string{
		"otpauth://totp/",
		"secret=" + NormalizeSecret(s),
		"issuer=",
		"algorithm=SHA1",
		"digits=6",
		"period=30",
		// 图标：少数验证器会用它，其余按规范忽略；地址必须公网可达且不可变
		"image=",
		url.QueryEscape(IconURL),
	} {
		if !strings.Contains(uri, want) {
			t.Errorf("otpauth 链接缺少 %q: %s", want, uri)
		}
	}
}

func TestNormalizeSecretToleratesUserInput(t *testing.T) {
	// 用户从验证器抄回来时常带空格、连字符或小写
	for _, in := range []string{
		rfcSecret,
		"gezdgnbvgy3tqojqgezdgnbvgy3tqojq",
		"GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ",
		"GEZD-GNBV-GY3T-QOJQ-GEZD-GNBV-GY3T-QOJQ",
	} {
		got, err := Code(in, time.Unix(59, 0).UTC())
		if err != nil {
			t.Fatalf("规整后应可解码: %q → %v", in, err)
		}
		if got != "287082" {
			t.Errorf("%q 规整后算出的口令 = %s，期望 287082", in, got)
		}
	}
}

func TestRecoveryCodes(t *testing.T) {
	codes, err := GenerateRecoveryCodes(RecoveryCodeCount)
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != RecoveryCodeCount {
		t.Fatalf("应生成 %d 个恢复码，实际 %d", RecoveryCodeCount, len(codes))
	}
	seen := map[string]bool{}
	for _, c := range codes {
		if seen[c] {
			t.Errorf("恢复码重复: %s", c)
		}
		seen[c] = true
		// 形如 XXXXX-XXXXX
		if len(c) != RecoveryCodeChars+1 || c[recoveryGroup] != '-' {
			t.Errorf("恢复码格式异常: %q", c)
		}
		// 不含易混字符
		for _, ch := range NormalizeRecoveryCode(c) {
			if !strings.ContainsRune(recoveryAlphabet, ch) {
				t.Errorf("恢复码含表外字符 %q: %s", ch, c)
			}
		}
	}
}

func TestNormalizeRecoveryCode(t *testing.T) {
	want := "ABCDE23456"
	for _, in := range []string{"ABCDE-23456", "abcde23456", "ABCDE 23456", " ABCDE-23456 "} {
		if got := NormalizeRecoveryCode(in); got != want {
			t.Errorf("NormalizeRecoveryCode(%q) = %q，期望 %q", in, got, want)
		}
	}
}
