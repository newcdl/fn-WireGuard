// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package agentapi

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"fnwg/internal/model"
)

// Client 通过 Unix Domain Socket 调用特权代理，实现 Core 接口。
type Client struct {
	path string
	seq  atomic.Int64
	mu   sync.Mutex
	conn net.Conn
	dec  *json.Decoder
	enc  *json.Encoder
}

// NewClient 创建客户端。
func NewClient(path string) *Client { return &Client{path: path} }

// Path 返回 socket 路径。
func (c *Client) Path() string { return c.path }

// connect 建立（或复用）连接。
func (c *Client) connect(ctx context.Context) error {
	if c.conn != nil {
		return nil
	}
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "unix", c.path)
	if err != nil {
		return err
	}
	c.conn = conn
	c.dec = json.NewDecoder(bufio.NewReader(conn))
	c.enc = json.NewEncoder(conn)
	return nil
}

func (c *Client) reset() {
	if c.conn != nil {
		_ = c.conn.Close()
	}
	c.conn, c.dec, c.enc = nil, nil, nil
}

// call 发送一次请求并解析响应。
func (c *Client) call(ctx context.Context, method string, params any, out any) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.connect(ctx); err != nil {
		return errors.New("连接特权代理失败（请确认 fnwg-agent 正在运行）: " + err.Error())
	}
	id := c.seq.Add(1)
	req := Request{ID: id, Method: method}
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return err
		}
		req.Params = b
	}

	done := make(chan error, 1)
	go func() {
		if err := c.enc.Encode(&req); err != nil {
			done <- err
			return
		}
		var resp Response
		if err := c.dec.Decode(&resp); err != nil {
			done <- err
			return
		}
		if !resp.OK {
			done <- errors.New(resp.Error)
			return
		}
		if out != nil && len(resp.Result) > 0 {
			done <- json.Unmarshal(resp.Result, out)
			return
		}
		done <- nil
	}()

	select {
	case <-ctx.Done():
		c.reset()
		return ctx.Err()
	case err := <-done:
		if err != nil {
			// 协议层错误说明连接状态不可信，丢弃后由下次调用重连。
			if !isBusinessError(err) {
				c.reset()
			}
			return err
		}
		return nil
	}
}

// isBusinessError 判断是否为代理返回的业务错误（此时连接仍然可用）。
func isBusinessError(err error) bool {
	var ne net.Error
	return !errors.As(err, &ne)
}

// Ping 探活。
func (c *Client) Ping(ctx context.Context) error {
	return c.call(ctx, MethodPing, nil, nil)
}

// Reconcile 触发一次收敛。
func (c *Client) Reconcile(ctx context.Context) ([]string, error) {
	var out struct {
		Actions []string `json:"actions"`
	}
	if err := c.call(ctx, MethodReconcile, nil, &out); err != nil {
		return nil, err
	}
	return out.Actions, nil
}

// Status 获取实时状态。
func (c *Client) Status(ctx context.Context) (model.Status, error) {
	var st model.Status
	err := c.call(ctx, MethodStatus, nil, &st)
	return st, err
}

// Health 获取健康度。
func (c *Client) Health(ctx context.Context) (model.Health, error) {
	var h model.Health
	err := c.call(ctx, MethodHealth, nil, &h)
	if err != nil {
		return model.Health{AgentUp: false, Error: err.Error()}, err
	}
	h.AgentUp = true
	return h, nil
}

// DeleteInterface 删除接口。
func (c *Client) DeleteInterface(ctx context.Context, name string) error {
	return c.call(ctx, MethodDeleteInterface, DeleteInterfaceParams{Name: name}, nil)
}

// InspectNetwork 网络自检。
func (c *Client) InspectNetwork(ctx context.Context) (model.NetworkReport, error) {
	var rep model.NetworkReport
	err := c.call(ctx, MethodNetInspect, nil, &rep)
	return rep, err
}

// RepairNetwork 清除残留的危险路由。
func (c *Client) RepairNetwork(ctx context.Context) ([]string, error) {
	var out struct {
		Actions []string `json:"actions"`
	}
	if err := c.call(ctx, MethodNetRepair, nil, &out); err != nil {
		return nil, err
	}
	return out.Actions, nil
}

// CleanupNetwork 删除本应用创建的全部内核对象。
func (c *Client) CleanupNetwork(ctx context.Context) ([]string, error) {
	var out struct {
		Actions []string `json:"actions"`
	}
	if err := c.call(ctx, MethodNetCleanup, nil, &out); err != nil {
		return nil, err
	}
	return out.Actions, nil
}

// DeleteForeignInterface 删除一个不属于本应用的 WireGuard 网卡（疑似残留）。
func (c *Client) DeleteForeignInterface(ctx context.Context, name string) ([]string, error) {
	var out struct {
		Actions []string `json:"actions"`
	}
	if err := c.call(ctx, MethodNetDeleteForeign, DeleteForeignInterfaceParams{Name: name}, &out); err != nil {
		return nil, err
	}
	return out.Actions, nil
}

// WaitReady 轮询等待代理就绪。
func (c *Client) WaitReady(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if err := c.Ping(ctx); err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("等待特权代理就绪超时")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(300 * time.Millisecond):
		}
	}
}
