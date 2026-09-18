// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 newcdl <newcdl@163.com>

package dnsserver

import (
	"encoding/binary"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// buildQuery 构造一个常规的单问题 DNS 查询报文。
func buildQuery(name string, qtype uint16) []byte {
	b := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	for _, label := range strings.Split(name, ".") {
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	b = append(b, 0)
	b = append(b, byte(qtype>>8), byte(qtype), 0x00, 0x01)
	return b
}

func TestParseQuestionAndBuildAnswer(t *testing.T) {
	query := buildQuery("NAS.Lan", typeA)
	q, ok := ParseQuestion(query)
	if !ok {
		t.Fatal("常规查询应能解析")
	}
	if q.Name != "nas.lan" {
		t.Fatalf("名字应归一化为小写，实际 %q", q.Name)
	}
	if q.QType != typeA {
		t.Fatalf("查询类型不对: %d", q.QType)
	}

	resp := BuildAnswer(query, q, []net.IP{net.ParseIP("192.168.1.5")})
	if binary.BigEndian.Uint16(resp[0:2]) != 0x1234 {
		t.Fatal("应复用客户端的事务 ID")
	}
	if binary.BigEndian.Uint16(resp[2:4])&0x8000 == 0 {
		t.Fatal("QR 位应为 1（这是响应）")
	}
	if n := binary.BigEndian.Uint16(resp[6:8]); n != 1 {
		t.Fatalf("ANCOUNT 应为 1，实际 %d", n)
	}
	// 问题段应原样回带
	if got := resp[12:q.End]; string(got) != string(query[12:q.End]) {
		t.Fatal("问题段应原样回带")
	}
	// 答案名字应是指向问题段的压缩指针
	if resp[q.End] != 0xC0 || resp[q.End+1] != 0x0C {
		t.Fatal("答案的名字应压缩指向问题段（0xC0 0x0C）")
	}
	if ip := net.IP(resp[len(resp)-4:]); !ip.Equal(net.ParseIP("192.168.1.5")) {
		t.Fatalf("应答地址不对: %v", ip)
	}
}

func TestBuildAnswerWithoutRecordsIsEmptyAnswer(t *testing.T) {
	query := buildQuery("nas", typeA)
	q, _ := ParseQuestion(query)
	resp := BuildAnswer(query, q, nil)
	if n := binary.BigEndian.Uint16(resp[6:8]); n != 0 {
		t.Fatalf("空答案的 ANCOUNT 应为 0，实际 %d", n)
	}
	if rc := binary.BigEndian.Uint16(resp[2:4]) & 0x000F; rc != 0 {
		t.Fatalf("应为 NOERROR(0)，实际 %d", rc)
	}
}

func TestParseQuestionRejectsGarbage(t *testing.T) {
	for _, bad := range [][]byte{
		{},
		{0x12, 0x34},
		append(buildQuery("a", typeA)[:12], 0xFF, 0xFF),
	} {
		if _, ok := ParseQuestion(bad); ok {
			t.Fatalf("畸形报文不该被解析成功: %v", bad)
		}
	}
	// 多问题查询应被拒绝（只处理单问题）
	multi := buildQuery("a", typeA)
	binary.BigEndian.PutUint16(multi[4:6], 2)
	if _, ok := ParseQuestion(multi); ok {
		t.Fatal("多问题查询应被拒绝")
	}
}

func TestLookupMatchesSuffixesButNotForeignDomains(t *testing.T) {
	s := New(nil)
	s.Sync(Config{Records: []Record{{Name: "NAS", IP: net.ParseIP("10.0.0.5")}}})
	for _, name := range []string{"nas", "nas.lan", "nas.local", "nas.home"} {
		if _, ok := s.lookupLocked(name); !ok {
			t.Fatalf("%s 应命中本地记录", name)
		}
	}
	for _, name := range []string{"nas.example.com", "other.lan", "naslan"} {
		if _, ok := s.lookupLocked(name); ok {
			t.Fatalf("%s 不该命中本地记录", name)
		}
	}
}

func TestLookupIgnoresInvalidIP(t *testing.T) {
	s := New(nil)
	s.Sync(Config{Records: []Record{
		{Name: "bad", IP: net.ParseIP("fd00::1")}, // IPv6 目前不支持，应被丢弃
		{Name: "ok", IP: net.ParseIP("10.0.0.9")},
	}})
	if _, ok := s.lookupLocked("bad"); ok {
		t.Fatal("IPv6 记录应被忽略")
	}
	if _, ok := s.lookupLocked("ok"); !ok {
		t.Fatal("IPv4 记录应保留")
	}
}

// freePort 借一个空闲高位端口（测试环境通常没有绑定 53 的权限）。
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	p := l.LocalAddr().(*net.UDPAddr).Port
	_ = l.Close()
	return p
}

func queryUDP(t *testing.T, addr string, query []byte) []byte {
	t.Helper()
	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(query); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("读取应答失败（解析器可能没在监听）: %v", err)
	}
	return buf[:n]
}

func TestServerAnswersLocalRecord(t *testing.T) {
	port := freePort(t)
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))

	s := New(nil)
	defer s.Close()
	s.Sync(Config{
		Listen:  []string{addr},
		Records: []Record{{Name: "nas", IP: net.ParseIP("192.168.1.5")}},
	})

	resp := queryUDP(t, addr, buildQuery("nas.lan", typeA))
	if n := binary.BigEndian.Uint16(resp[6:8]); n != 1 {
		t.Fatalf("应返回 1 条 A 记录，实际 %d", n)
	}
	if ip := net.IP(resp[len(resp)-4:]); !ip.Equal(net.ParseIP("192.168.1.5")) {
		t.Fatalf("解析结果不对: %v", ip)
	}

	// 本地名字的 AAAA 查询应回「空答案」，而不是丢给上游
	aaaa := queryUDP(t, addr, buildQuery("nas", 28))
	if n := binary.BigEndian.Uint16(aaaa[6:8]); n != 0 {
		t.Fatalf("AAAA 应为空答案，实际 ANCOUNT=%d", n)
	}

	// 关闭监听后不应再收到应答
	s.Sync(Config{})
	if got := s.Status(true).Listen; len(got) != 0 {
		t.Fatalf("停止后不应还有监听: %v", got)
	}
}

// TestServerForwardsUnknown 非本地名字必须原样转发给上游。
func TestServerForwardsUnknown(t *testing.T) {
	// 上游桩：把收到的查询原样改一个字节后回包，便于确认确实是转发过去的
	up, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := up.ReadFromUDP(buf)
			if err != nil {
				return
			}
			reply := make([]byte, n)
			copy(reply, buf[:n])
			reply[3] = 0xAB // 打一个可识别的记号
			_, _ = up.WriteToUDP(reply, from)
		}
	}()

	port := freePort(t)
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	s := New(nil)
	defer s.Close()
	s.Sync(Config{
		Listen:    []string{addr},
		Records:   []Record{{Name: "nas", IP: net.ParseIP("192.168.1.5")}},
		Upstreams: []string{up.LocalAddr().String()},
	})

	resp := queryUDP(t, addr, buildQuery("www.example.com", typeA))
	if resp[3] != 0xAB {
		t.Fatal("非本地名字应转发给上游并原样回包")
	}
}

// TestServerWithoutUpstreamReturnsServfail 既不是本地记录、又没有上游时，
// 必须明确回 SERVFAIL，而不是静默超时（设备侧会一直等）。
func TestServerWithoutUpstreamReturnsServfail(t *testing.T) {
	port := freePort(t)
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	s := New(nil)
	defer s.Close()
	s.Sync(Config{Listen: []string{addr}})

	resp := queryUDP(t, addr, buildQuery("www.example.com", typeA))
	if rc := binary.BigEndian.Uint16(resp[2:4]) & 0x000F; rc != 3 {
		t.Fatalf("应为 SERVFAIL(3)，实际 %d", rc)
	}
}
