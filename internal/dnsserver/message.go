// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 newcdl <newcdl@163.com>

package dnsserver

import (
	"encoding/binary"
	"net"
	"strings"
)

// 本文件只实现 DNS 报文里**我们真正需要的那一小部分**：解析问题段、组装 A 记录应答。
// 其余类型与内容一律原样转发给上游，不解释也不改写 —— 解释得越多，
// 出错的机会越大，而这里的目标只是「让家里设备名能被解析」。

const (
	typeA   uint16 = 1
	classIN uint16 = 1

	rcodeNoError  byte = 0
	rcodeServFail byte = 3
)

// Question 是一次查询的问题段。
type Question struct {
	// Name 已归一化：小写、无末尾点。
	Name string
	// QType 查询类型（A=1）。
	QType uint16
	// End 是问题段结束的偏移。构造响应时直接复制 query[12:End] 即可原样回带问题段。
	End int
}

// ParseQuestion 解析查询报文的问题段。
//
// 只接受「单问题」的常规查询；其余（多问题、截断报文）一律返回 false，
// 由调用方决定忽略 —— 绝不靠猜来构造应答。
func ParseQuestion(msg []byte) (Question, bool) {
	var q Question
	if len(msg) < 12 {
		return q, false
	}
	if binary.BigEndian.Uint16(msg[4:6]) != 1 {
		return q, false
	}
	name, off, ok := decodeName(msg, 12)
	if !ok {
		return q, false
	}
	if off+4 > len(msg) {
		return q, false
	}
	q.Name = name
	q.QType = binary.BigEndian.Uint16(msg[off : off+2])
	q.End = off + 4
	return q, true
}

// BuildAnswer 构造应答：原样回带问题段，再附上若干 A 记录。
//
// ips 为空时就是「NOERROR + 空答案」—— 用于本地名字的非 A 查询，
// 明确告诉客户端「这个名字存在、但没有这种记录」，而不是把它丢给上游去猜。
func BuildAnswer(query []byte, q Question, ips []net.IP) []byte {
	v4 := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		if b := ip.To4(); b != nil {
			v4 = append(v4, b)
		}
	}
	out := make([]byte, 0, q.End+16*len(v4))
	out = append(out, buildHeader(query, rcodeNoError, uint16(len(v4)))...)
	out = append(out, query[12:q.End]...)
	for _, ip := range v4 {
		// 名字用压缩指针指回问题段（偏移 12），不必重复编码域名
		out = append(out, 0xC0, 0x0C)
		out = append(out, byte(typeA>>8), byte(typeA))
		out = append(out, byte(classIN>>8), byte(classIN))
		out = append(out, 0, 0, 0, 60) // TTL 60 秒：家里地址变动很少，但也不必缓存太久
		out = append(out, 0, 4)
		out = append(out, ip...)
	}
	return out
}

// BuildFailure 构造失败应答（SERVFAIL），用于无法转发或转发超时。
func BuildFailure(query []byte, q Question) []byte {
	out := buildHeader(query, rcodeServFail, 0)
	return append(out, query[12:q.End]...)
}

func buildHeader(query []byte, rcode byte, ancount uint16) []byte {
	h := make([]byte, 12, 12+16)
	copy(h[0:2], query[0:2]) // 复用客户端的事务 ID
	reqFlags := binary.BigEndian.Uint16(query[2:4])
	// QR=1（这是响应）、RD 原样回带、RA=1（本端可递归）、RCODE 见参数
	flags := uint16(0x8000) | (reqFlags & 0x0100) | 0x0080 | uint16(rcode&0x0F)
	binary.BigEndian.PutUint16(h[2:4], flags)
	binary.BigEndian.PutUint16(h[4:6], 1) // QDCOUNT
	binary.BigEndian.PutUint16(h[6:8], ancount)
	return h
}

// decodeName 解码域名，返回归一化后的名字与「名字之后」的偏移。
//
// 兼容压缩指针，并对指针链做跳数上限保护：问题段通常不压缩，
// 但不能假设对面发来的东西是规范的。
func decodeName(msg []byte, off int) (string, int, bool) {
	var sb strings.Builder
	pos := off
	end := -1
	for hops := 0; hops < 128; hops++ {
		if pos >= len(msg) {
			return "", 0, false
		}
		l := int(msg[pos])
		if l == 0 {
			pos++
			if end < 0 {
				end = pos
			}
			break
		}
		if l&0xC0 == 0xC0 {
			if pos+1 >= len(msg) {
				return "", 0, false
			}
			if end < 0 {
				end = pos + 2
			}
			pos = int(binary.BigEndian.Uint16(msg[pos:pos+2]) & 0x3FFF)
			continue
		}
		if l > 63 || pos+1+l > len(msg) {
			return "", 0, false
		}
		if sb.Len() > 0 {
			sb.WriteByte('.')
		}
		sb.Write(msg[pos+1 : pos+1+l])
		pos += 1 + l
	}
	if end < 0 {
		return "", 0, false
	}
	return strings.ToLower(sb.String()), end, true
}
