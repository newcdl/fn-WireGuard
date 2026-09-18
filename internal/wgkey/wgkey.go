// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 newcdl <newcdl@163.com>

// Package wgkey 负责 Curve25519 密钥与预共享密钥的生成与校验。
// 仅依赖标准库，便于在任意平台进行单元测试。
package wgkey

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
)

// KeyLen 是 WireGuard 密钥字节长度。
const KeyLen = 32

// Generate 生成一对 Curve25519 密钥，返回 base64 编码的私钥与公钥。
func Generate() (priv string, pub string, err error) {
	raw := make([]byte, KeyLen)
	if _, err = rand.Read(raw); err != nil {
		return "", "", err
	}
	clamp(raw)
	pub, err = derive(raw)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(raw), pub, nil
}

// PublicKey 由私钥推导公钥。
func PublicKey(privB64 string) (string, error) {
	raw, err := decode(privB64)
	if err != nil {
		return "", err
	}
	clamp(raw)
	return derive(raw)
}

func derive(raw []byte) (string, error) {
	// crypto/ecdh 的 X25519 会对标量做与 WireGuard 一致的钳位处理。
	pk, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(pk.PublicKey().Bytes()), nil
}

// GeneratePSK 生成预共享密钥。
func GeneratePSK() (string, error) {
	raw := make([]byte, KeyLen)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

// Validate 校验字符串是否为合法的 32 字节 base64 密钥。
func Validate(k string) bool {
	_, err := decode(k)
	return err == nil
}

func decode(k string) ([]byte, error) {
	if k == "" {
		return nil, errors.New("密钥为空")
	}
	raw, err := base64.StdEncoding.DecodeString(k)
	if err != nil {
		return nil, errors.New("密钥不是合法的 base64")
	}
	if len(raw) != KeyLen {
		return nil, errors.New("密钥长度不是 32 字节")
	}
	return raw, nil
}

// clamp 执行 Curve25519 标量钳位。
func clamp(k []byte) {
	k[0] &= 248
	k[31] &= 127
	k[31] |= 64
}
