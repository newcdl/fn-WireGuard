// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

// Package dnsserver 实现「内网域名解析」：一个只绑定隧道地址的极简 DNS 应答器。
//
// 为什么自己实现而不用通用 DNS 库：这里只需要「A 记录应答 + 其余转发」两件事，
// 引入通用库会显著增大二进制（本项目对体积敏感，见 ROADMAP R6），而协议里真正
// 需要的部分（问题段解析、A 记录组装、原样转发）代码量很小。
//
// 安全边界（与内网访问、设备隔离同级）：
//
//  1. 只监听**本应用创建连接的隧道地址**，绝不监听 0.0.0.0:53，
//     因此不会与 NAS 上已有的 DNS 服务（Docker / AdGuard 等）抢端口；
//  2. 只对用户显式登记的名字做权威应答，其余查询原样转发给连接里配置的上游 DNS；
//  3. 不修改系统任何 DNS 配置（/etc/resolv.conf 一律不碰）。
package dnsserver

import (
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"fnwg/internal/model"
)

// forwardTimeout 是转发上游 DNS 的超时。取 3 秒与通知投递一致：
// 太长会让设备侧解析出现明显卡顿，太短则容易误判上游不可用。
const forwardTimeout = 3 * time.Second

// Config 是一次同步的目标状态。
type Config struct {
	// Listen 监听地址（隧道地址，形如 10.10.0.1:53）。为空表示不监听任何地址。
	Listen []string
	// Records 需要权威应答的 A 记录。
	Records []Record
	// Upstreams 非本地查询的转发目标（可只填 IP，端口默认 53）。
	Upstreams []string
}

// Record 是一条权威 A 记录。
type Record struct {
	Name string
	IP   net.IP
}

// Server 管理监听与应答。
type Server struct {
	log *slog.Logger

	mu        sync.Mutex
	udp       map[string]*net.UDPConn
	tcp       map[string]net.Listener
	records   map[string]net.IP
	upstreams []string
	note      string

	queries atomic.Int64
	failed  atomic.Int64
}

// New 创建解析器（此时尚未监听任何地址，需调用 Sync）。
func New(log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	return &Server{
		log:     log,
		udp:     map[string]*net.UDPConn{},
		tcp:     map[string]net.Listener{},
		records: map[string]net.IP{},
	}
}

// Sync 把解析器调整到目标状态：增删监听、整体替换记录与上游。
//
// 单条监听失败只记录原因、不影响其它监听，也绝不返回错误中断收敛循环 ——
// 与内网访问一致：环境条件不满足时给出可读原因，让界面去告诉用户卡在哪一层。
func (s *Server) Sync(cfg Config) {
	s.mu.Lock()
	defer s.mu.Unlock()

	want := make(map[string]bool, len(cfg.Listen))
	for _, a := range cfg.Listen {
		if a = strings.TrimSpace(a); a != "" {
			want[a] = true
		}
	}
	for addr, c := range s.udp {
		if !want[addr] {
			_ = c.Close()
			delete(s.udp, addr)
		}
	}
	for addr, l := range s.tcp {
		if !want[addr] {
			_ = l.Close()
			delete(s.tcp, addr)
		}
	}

	// 记录与上游整体替换：解析器是无状态的纯查表，不需要增量维护。
	s.records = make(map[string]net.IP, len(cfg.Records))
	for _, r := range cfg.Records {
		if r.IP.To4() == nil {
			continue
		}
		s.records[normalizeName(r.Name)] = r.IP
	}
	s.upstreams = s.upstreams[:0]
	for _, u := range cfg.Upstreams {
		if a := normalizeAddr(u, "53"); a != "" {
			s.upstreams = append(s.upstreams, a)
		}
	}

	var notes []string
	for addr := range want {
		if _, ok := s.udp[addr]; ok {
			continue
		}
		if err := s.listen(addr); err != nil {
			notes = append(notes, addr+"："+err.Error())
		}
	}
	sort.Strings(notes)
	s.note = strings.Join(notes, "；")
}

// listen 同时监听 UDP 与 TCP。
//
// TCP 不是可选项：DNS 响应超过 UDP 报文长度时会置 TC 标志，客户端随即改用 TCP 重试；
// 不提供 TCP 的话，这类查询（记录多、或上游返回大报文时）会直接失败。
func (s *Server) listen(addr string) error {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	uc, err := net.ListenUDP("udp", ua)
	if err != nil {
		return err
	}
	s.udp[addr] = uc
	go s.serveUDP(uc)

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		// UDP 已可用，只告警不失败：绝大多数查询走 UDP
		s.log.Warn("内网域名解析的 TCP 监听失败（UDP 仍可用）", "addr", addr, "err", err)
		return nil
	}
	s.tcp[addr] = ln
	go s.serveTCP(ln)
	return nil
}

func (s *Server) serveUDP(conn *net.UDPConn) {
	buf := make([]byte, 2048)
	for {
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			return // 连接已被 Sync/Close 关闭
		}
		msg := make([]byte, n)
		copy(msg, buf[:n])
		go func() {
			if resp := s.answer(msg); resp != nil {
				_, _ = conn.WriteToUDP(resp, from)
			}
		}()
	}
}

func (s *Server) serveTCP(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go s.handleTCP(c)
	}
}

func (s *Server) handleTCP(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	for {
		// DNS over TCP 的报文带 2 字节长度前缀
		var lb [2]byte
		if _, err := io.ReadFull(c, lb[:]); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(lb[:]))
		if n == 0 {
			return
		}
		msg := make([]byte, n)
		if _, err := io.ReadFull(c, msg); err != nil {
			return
		}
		resp := s.answer(msg)
		if resp == nil {
			return
		}
		out := make([]byte, 2+len(resp))
		binary.BigEndian.PutUint16(out[:2], uint16(len(resp)))
		copy(out[2:], resp)
		if _, err := c.Write(out); err != nil {
			return
		}
	}
}

// answer 计算一次查询的应答。
//
// 返回 nil 表示报文无法解析：直接不回包，避免把畸形报文放大成反射源。
func (s *Server) answer(msg []byte) []byte {
	q, ok := ParseQuestion(msg)
	if !ok {
		return nil
	}
	s.queries.Add(1)

	s.mu.Lock()
	ip, found := s.lookupLocked(q.Name)
	upstream := ""
	if len(s.upstreams) > 0 {
		upstream = s.upstreams[0]
	}
	s.mu.Unlock()

	if found {
		if q.QType == typeA {
			return BuildAnswer(msg, q, []net.IP{ip})
		}
		return BuildAnswer(msg, q, nil)
	}
	if upstream == "" {
		s.failed.Add(1)
		return BuildFailure(msg, q)
	}
	resp, err := forward(msg, upstream)
	if err != nil {
		s.failed.Add(1)
		s.log.Debug("内网域名解析转发失败", "upstream", upstream, "err", err)
		return BuildFailure(msg, q)
	}
	return resp
}

// localSuffixes 是常见的内网域名后缀。
//
// 用户按习惯填「nas」时，设备上写 nas / nas.lan / nas.local 都应该能解析；
// 只对**用户显式登记过的名字**生效，因此不会去劫持任意域名（nas.baidu.com 不会命中）。
var localSuffixes = []string{"lan", "local", "home"}

func (s *Server) lookupLocked(name string) (net.IP, bool) {
	if ip, ok := s.records[name]; ok {
		return ip, true
	}
	for _, suf := range localSuffixes {
		if base, ok := strings.CutSuffix(name, "."+suf); ok {
			if ip, ok := s.records[base]; ok {
				return ip, true
			}
		}
	}
	return nil, false
}

// Status 返回解析器状态，供界面展示与排障。
func (s *Server) Status(enabled bool) model.DNSStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	addrs := make([]string, 0, len(s.udp))
	for a := range s.udp {
		addrs = append(addrs, a)
	}
	sort.Strings(addrs)
	return model.DNSStatus{
		Enabled: enabled,
		Listen:  addrs,
		Records: len(s.records),
		Queries: s.queries.Load(),
		Failed:  s.failed.Load(),
		Note:    s.note,
	}
}

// Close 关闭全部监听。
func (s *Server) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for addr, c := range s.udp {
		_ = c.Close()
		delete(s.udp, addr)
	}
	for addr, l := range s.tcp {
		_ = l.Close()
		delete(s.tcp, addr)
	}
}

func forward(query []byte, upstream string) ([]byte, error) {
	conn, err := net.DialTimeout("udp", upstream, forwardTimeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(forwardTimeout))
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func normalizeName(v string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(v), "."))
}

// normalizeAddr 补全端口：用户在上游里通常只填 IP。
func normalizeAddr(v, defPort string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(v); err == nil {
		return v
	}
	return net.JoinHostPort(v, defPort)
}
