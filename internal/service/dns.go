package service

import (
	"context"
	"fmt"
	"net"
	"strings"

	"fnwg/internal/store"
)

// DNSRecordInput 是内网域名记录的新增/编辑入参。
type DNSRecordInput struct {
	Name string `json:"name"`
	IP   string `json:"ip"`
	Note string `json:"note"`
}

// ListDNSRecords 返回全部内网域名记录。
func (s *Service) ListDNSRecords(ctx context.Context) ([]store.DNSRecord, error) {
	return s.Store.ListDNSRecords(ctx)
}

// CreateDNSRecord 新增内网域名记录。
func (s *Service) CreateDNSRecord(ctx context.Context, in DNSRecordInput, a Actor) (*store.DNSRecord, error) {
	name, ip, err := validateDNSRecord(in)
	if err != nil {
		return nil, err
	}
	r := &store.DNSRecord{Name: name, IP: ip, Note: strings.TrimSpace(in.Note)}
	if err := s.Store.CreateDNSRecord(ctx, r); err != nil {
		return nil, dnsWriteErr(err, name)
	}
	s.audit(ctx, a, "dns.create", "dns", fmt.Sprint(r.ID), "", name+" → "+ip, "ok", "")
	_ = s.reconcile(ctx)
	return r, nil
}

// UpdateDNSRecord 编辑内网域名记录。
func (s *Service) UpdateDNSRecord(ctx context.Context, id int64, in DNSRecordInput, a Actor) (*store.DNSRecord, error) {
	cur, err := s.Store.GetDNSRecord(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("记录不存在，请刷新页面后重试")
	}
	name, ip, err := validateDNSRecord(in)
	if err != nil {
		return nil, err
	}
	before := cur.Name + " → " + cur.IP
	cur.Name, cur.IP, cur.Note = name, ip, strings.TrimSpace(in.Note)
	if err := s.Store.UpdateDNSRecord(ctx, cur); err != nil {
		return nil, dnsWriteErr(err, name)
	}
	s.audit(ctx, a, "dns.update", "dns", fmt.Sprint(id), before, name+" → "+ip, "ok", "")
	_ = s.reconcile(ctx)
	return cur, nil
}

// DeleteDNSRecord 删除内网域名记录。
func (s *Service) DeleteDNSRecord(ctx context.Context, id int64, a Actor) error {
	cur, err := s.Store.GetDNSRecord(ctx, id)
	if err != nil {
		return fmt.Errorf("记录不存在，请刷新页面后重试")
	}
	if err := s.Store.DeleteDNSRecord(ctx, id); err != nil {
		return err
	}
	s.audit(ctx, a, "dns.delete", "dns", fmt.Sprint(id), cur.Name+" → "+cur.IP, "", "ok", "")
	_ = s.reconcile(ctx)
	return nil
}

// validateDNSRecord 校验并归一化一条记录。
//
// 名字限制在「字母/数字/连字符 + 点号」范围内：DNS 名字允许的东西比这多得多，
// 但这里服务的是「家里设备名」这一种用途，收紧范围能把打错字挡在保存之前。
func validateDNSRecord(in DNSRecordInput) (string, string, error) {
	name := store.NormalizeDNSName(in.Name)
	if name == "" {
		return "", "", fmt.Errorf("请填写主机名，例如 nas.lan")
	}
	if len(name) > 253 {
		return "", "", fmt.Errorf("主机名过长")
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			return "", "", fmt.Errorf("主机名格式不正确：点号之间不能为空，且每段不超过 63 个字符")
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if c != '-' && !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'z') {
				return "", "", fmt.Errorf("主机名只能用字母、数字、连字符与点号：%q", label)
			}
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return "", "", fmt.Errorf("主机名的每一段不能以连字符开头或结尾：%q", label)
		}
	}
	ip := net.ParseIP(strings.TrimSpace(in.IP))
	if ip == nil || ip.To4() == nil {
		return "", "", fmt.Errorf("请填写 IPv4 地址，例如 192.168.1.10")
	}
	return name, ip.To4().String(), nil
}

// dnsWriteErr 把唯一索引冲突翻译成人话。
func dnsWriteErr(err error, name string) error {
	msg := err.Error()
	if strings.Contains(msg, "UNIQUE") || strings.Contains(msg, "constraint") {
		return fmt.Errorf("「%s」已经有一条记录了：请直接编辑那一条，或换一个名字", name)
	}
	return err
}
