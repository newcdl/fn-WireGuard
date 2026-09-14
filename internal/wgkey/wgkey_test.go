package wgkey

import "testing"

func TestGenerateAndDerive(t *testing.T) {
	priv, pub, err := Generate()
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}
	if !Validate(priv) || !Validate(pub) {
		t.Fatal("生成的密钥未通过校验")
	}
	derived, err := PublicKey(priv)
	if err != nil {
		t.Fatalf("推导公钥失败: %v", err)
	}
	if derived != pub {
		t.Fatalf("推导的公钥与生成结果不一致: %s != %s", derived, pub)
	}
}

func TestGenerateUniqueness(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 32; i++ {
		priv, _, err := Generate()
		if err != nil {
			t.Fatal(err)
		}
		if seen[priv] {
			t.Fatal("生成了重复的私钥")
		}
		seen[priv] = true
	}
}

func TestValidateRejects(t *testing.T) {
	cases := []string{
		"",
		"not-base64!!",
		"YWJj", // 长度不足 32 字节
	}
	for _, c := range cases {
		if Validate(c) {
			t.Fatalf("非法密钥被误判为合法: %q", c)
		}
	}
}

func TestPSK(t *testing.T) {
	psk, err := GeneratePSK()
	if err != nil {
		t.Fatal(err)
	}
	if !Validate(psk) {
		t.Fatal("预共享密钥未通过校验")
	}
}
