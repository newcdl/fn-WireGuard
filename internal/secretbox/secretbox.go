// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

// Package secretbox 提供基于 AES-256-GCM 的静态数据加密。
// 用于把 WireGuard 私钥 / PSK 以密文形式落库，避免数据库或备份文件泄露时直接暴露私钥。
package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Box 是加解密器。
type Box struct {
	aead cipher.AEAD
}

// LoadOrCreate 读取主密钥；不存在时生成 32 字节随机密钥并以 0600 落盘。
func LoadOrCreate(path string) (*Box, error) {
	key, err := os.ReadFile(path)
	switch {
	case err == nil:
		if len(key) != 32 {
			return nil, fmt.Errorf("主密钥长度非法（%d），期望 32 字节", len(key))
		}
	case errors.Is(err, os.ErrNotExist):
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o770); err != nil {
			return nil, err
		}
		tmp := path + ".tmp"
		if err := os.WriteFile(tmp, key, 0o600); err != nil {
			return nil, err
		}
		if err := os.Rename(tmp, path); err != nil {
			return nil, err
		}
	default:
		return nil, err
	}
	return New(key)
}

// New 用给定密钥构造 Box。
func New(key []byte) (*Box, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Box{aead: aead}, nil
}

// Seal 加密明文，返回 nonce||ciphertext。
func (b *Box) Seal(plain []byte) ([]byte, error) {
	if len(plain) == 0 {
		return nil, nil
	}
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return b.aead.Seal(nonce, nonce, plain, nil), nil
}

// Open 解密 Seal 的产物。空输入返回空字符串。
func (b *Box) Open(blob []byte) ([]byte, error) {
	if len(blob) == 0 {
		return nil, nil
	}
	ns := b.aead.NonceSize()
	if len(blob) < ns {
		return nil, errors.New("密文长度非法")
	}
	return b.aead.Open(nil, blob[:ns], blob[ns:], nil)
}

// SealString 便捷方法。
func (b *Box) SealString(s string) ([]byte, error) { return b.Seal([]byte(s)) }

// OpenString 便捷方法。
func (b *Box) OpenString(blob []byte) (string, error) {
	v, err := b.Open(blob)
	return string(v), err
}
