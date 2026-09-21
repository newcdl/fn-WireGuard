// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package agentapi

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"time"
)

// Server 在 Unix Domain Socket 上暴露 Core 能力。
type Server struct {
	path    string
	handler Core
	log     *slog.Logger
	group   string
	ln      net.Listener
}

// NewServer 创建代理服务。
func NewServer(path string, group string, h Core, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{path: path, group: group, handler: h, log: logger}
}

// Listen 监听 socket 并把访问权限收敛到指定用户组。
func (s *Server) Listen() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o770); err != nil {
		return err
	}
	// 清理上次异常退出遗留的 socket 文件
	if _, err := os.Stat(s.path); err == nil {
		_ = os.Remove(s.path)
	}
	ln, err := net.Listen("unix", s.path)
	if err != nil {
		return err
	}
	s.ln = ln
	s.restrict()
	s.log.Info("特权代理已启动", "socket", s.path, "group", s.group)
	return nil
}

// restrict 把 socket 权限设置为 0660 并归属指定用户组，避免其他应用调用特权接口。
func (s *Server) restrict() {
	mode := os.FileMode(0o660)
	gid := -1
	if s.group != "" {
		if g, err := user.LookupGroup(s.group); err == nil {
			if v, err := strconv.Atoi(g.Gid); err == nil {
				gid = v
			}
		}
	}
	if gid < 0 {
		// 找不到目标用户组时退化为 0600，只允许与代理同用户访问（更安全）。
		mode = 0o600
		s.log.Warn("未找到运行用户组，socket 权限退化为 0600", "group", s.group)
	} else if err := os.Chown(s.path, 0, gid); err != nil {
		s.log.Warn("设置 socket 属组失败", "err", err)
	}
	if err := os.Chmod(s.path, mode); err != nil {
		s.log.Warn("设置 socket 权限失败", "err", err)
	}
}

// Serve 处理连接直到 ctx 结束。
func (s *Server) Serve(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		if s.ln != nil {
			_ = s.ln.Close()
		}
	}()
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go s.handle(conn)
	}
}

// Close 关闭监听。
func (s *Server) Close() error {
	if s.ln != nil {
		return s.ln.Close()
	}
	return nil
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Minute))
	dec := json.NewDecoder(bufio.NewReader(conn))
	enc := json.NewEncoder(conn)
	for {
		var req Request
		if err := dec.Decode(&req); err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				s.log.Debug("读取代理请求失败", "err", err)
			}
			return
		}
		resp := s.dispatch(conn, &req)
		if err := enc.Encode(resp); err != nil {
			return
		}
	}
}

func (s *Server) dispatch(conn net.Conn, req *Request) Response {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	resp := Response{ID: req.ID}

	switch req.Method {
	case MethodPing:
		resp.OK = true
		resp.Result = mustJSON(map[string]string{"pong": "ok"})
		return resp
	case MethodReconcile:
		actions, err := s.handler.Reconcile(ctx)
		if err != nil {
			return fail(resp, err)
		}
		resp.OK = true
		resp.Result = mustJSON(map[string]any{"actions": actions})
		return resp
	case MethodStatus:
		st, err := s.handler.Status(ctx)
		if err != nil {
			return fail(resp, err)
		}
		resp.OK = true
		resp.Result = mustJSON(st)
		return resp
	case MethodHealth:
		h, err := s.handler.Health(ctx)
		if err != nil {
			return fail(resp, err)
		}
		resp.OK = true
		resp.Result = mustJSON(h)
		return resp
	case MethodNetInspect:
		rep, err := s.handler.InspectNetwork(ctx)
		if err != nil {
			return fail(resp, err)
		}
		resp.OK = true
		resp.Result = mustJSON(rep)
		return resp
	case MethodNetRepair:
		actions, err := s.handler.RepairNetwork(ctx)
		if err != nil {
			return fail(resp, err)
		}
		resp.OK = true
		resp.Result = mustJSON(map[string]any{"actions": actions})
		return resp
	case MethodNetCleanup:
		actions, err := s.handler.CleanupNetwork(ctx)
		if err != nil {
			return fail(resp, err)
		}
		resp.OK = true
		resp.Result = mustJSON(map[string]any{"actions": actions})
		return resp
	case MethodInspectRun:
		var p InspectRunParams
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return fail(resp, errors.New("参数解析失败"))
		}
		res, err := s.handler.RunInspect(ctx, p.UserID, p.Username, p.SrcIP)
		if err != nil {
			return fail(resp, err)
		}
		resp.OK = true
		resp.Result = mustJSON(res)
		return resp
	case MethodBackupRun:
		var p BackupRunParams
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return fail(resp, errors.New("参数解析失败"))
		}
		res, err := s.handler.RunBackupPlan(ctx, p.UserID, p.Username, p.SrcIP)
		if err != nil {
			return fail(resp, err)
		}
		resp.OK = true
		resp.Result = mustJSON(res)
		return resp
	case MethodBackupDirInspect:
		var p BackupDirParams
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return fail(resp, errors.New("参数解析失败"))
		}
		info, err := s.handler.InspectBackupDir(ctx, p.Dir)
		if err != nil {
			return fail(resp, err)
		}
		resp.OK = true
		resp.Result = mustJSON(info)
		return resp
	case MethodBackupCopyRead:
		var p BackupCopyReadParams
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return fail(resp, errors.New("参数解析失败"))
		}
		raw, err := s.handler.ReadBackupCopy(ctx, p.Dir, p.Name)
		if err != nil {
			return fail(resp, err)
		}
		resp.OK = true
		resp.Result = mustJSON(BackupCopyRawResult{Raw: raw})
		return resp
	case MethodBackupCopyWrite:
		var p BackupCopyWriteParams
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return fail(resp, errors.New("参数解析失败"))
		}
		name, err := s.handler.WriteBackupCopy(ctx, p.Dir, p.BackupID, p.UserID, p.Username, p.SrcIP)
		if err != nil {
			return fail(resp, err)
		}
		resp.OK = true
		resp.Result = mustJSON(BackupCopyWriteResult{Name: name})
		return resp
	case MethodNetDeleteForeign:
		var p DeleteForeignInterfaceParams
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return fail(resp, errors.New("参数解析失败"))
		}
		if err := validateIfaceName(p.Name); err != nil {
			return fail(resp, err)
		}
		actions, err := s.handler.DeleteForeignInterface(ctx, p.Name)
		if err != nil {
			return fail(resp, err)
		}
		resp.OK = true
		resp.Result = mustJSON(map[string]any{"actions": actions})
		return resp
	case MethodDeleteInterface:
		var p DeleteInterfaceParams
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return fail(resp, errors.New("参数解析失败"))
		}
		if err := validateIfaceName(p.Name); err != nil {
			return fail(resp, err)
		}
		if err := s.handler.DeleteInterface(ctx, p.Name); err != nil {
			return fail(resp, err)
		}
		resp.OK = true
		resp.Result = mustJSON(map[string]bool{"deleted": true})
		return resp
	default:
		return fail(resp, errors.New("未知方法: "+req.Method))
	}
}

func fail(resp Response, err error) Response {
	resp.OK = false
	resp.Error = err.Error()
	return resp
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

// validateIfaceName 严格校验接口名，杜绝越权操作任意 link。
func validateIfaceName(name string) error {
	if name == "" || len(name) > 15 {
		return errors.New("接口名非法")
	}
	for i, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_':
		default:
			return errors.New("接口名含非法字符")
		}
		if i == 0 && (r < 'a' || r > 'z') {
			return errors.New("接口名必须以字母开头")
		}
	}
	return nil
}
