package api

import (
	"net/http"
	"time"

	"fnwg/internal/service"
)

// ---------------------------------------------------------------- 接口

func (s *Server) handleListInterfaces(w http.ResponseWriter, r *http.Request) {
	list, err := s.svc.ListInterfaces(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": list})
}

func (s *Server) handleGetInterface(w http.ResponseWriter, r *http.Request) {
	id, ok := s.idOrFail(w, r)
	if !ok {
		return
	}
	it, err := s.svc.GetInterface(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, it)
}

func (s *Server) handleCreateInterface(w http.ResponseWriter, r *http.Request) {
	var in service.CreateInterfaceInput
	if err := decodeBody(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	it, err := s.svc.CreateInterface(r.Context(), in, actorOf(r))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, it)
}

func (s *Server) handleUpdateInterface(w http.ResponseWriter, r *http.Request) {
	id, ok := s.idOrFail(w, r)
	if !ok {
		return
	}
	var in service.CreateInterfaceInput
	if err := decodeBody(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	it, err := s.svc.UpdateInterface(r.Context(), id, in, actorOf(r))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, it)
}

func (s *Server) handleDeleteInterface(w http.ResponseWriter, r *http.Request) {
	id, ok := s.idOrFail(w, r)
	if !ok {
		return
	}
	if err := s.svc.DeleteInterface(r.Context(), id, actorOf(r)); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
}

func (s *Server) handleToggleInterface(w http.ResponseWriter, r *http.Request) {
	id, ok := s.idOrFail(w, r)
	if !ok {
		return
	}
	var in struct {
		Enabled bool `json:"enabled"`
	}
	if err := decodeBody(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.svc.ToggleInterface(r.Context(), id, in.Enabled, actorOf(r)); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"enabled": in.Enabled})
}

// handleSetLanAccess 切换「允许设备访问家里内网」。
func (s *Server) handleSetLanAccess(w http.ResponseWriter, r *http.Request) {
	id, ok := s.idOrFail(w, r)
	if !ok {
		return
	}
	var in struct {
		Enabled bool `json:"enabled"`
	}
	if err := decodeBody(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	it, err := s.svc.SetLanAccess(r.Context(), id, in.Enabled, actorOf(r))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, it)
}

// handleSetPeerIsolation 切换「设备间隔离」。
func (s *Server) handleSetPeerIsolation(w http.ResponseWriter, r *http.Request) {
	id, ok := s.idOrFail(w, r)
	if !ok {
		return
	}
	var in struct {
		Enabled bool `json:"enabled"`
	}
	if err := decodeBody(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	it, err := s.svc.SetPeerIsolation(r.Context(), id, in.Enabled, actorOf(r))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, it)
}

func (s *Server) handleApplyInterface(w http.ResponseWriter, r *http.Request) {
	actions, err := s.svc.ReconcileNow(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"actions": actions})
}

func (s *Server) handleRevealInterfaceKey(w http.ResponseWriter, r *http.Request) {
	id, ok := s.idOrFail(w, r)
	if !ok {
		return
	}
	key, err := s.svc.RevealPrivateKey(r.Context(), id, actorOf(r))
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"private_key": key})
}

func (s *Server) handleRotateInterfaceKey(w http.ResponseWriter, r *http.Request) {
	id, ok := s.idOrFail(w, r)
	if !ok {
		return
	}
	pub, err := s.svc.RegenerateInterfaceKey(r.Context(), id, actorOf(r))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"public_key": pub})
}

func (s *Server) handleInterfaceConf(w http.ResponseWriter, r *http.Request) {
	id, ok := s.idOrFail(w, r)
	if !ok {
		return
	}
	name, conf, err := s.svc.InterfaceConf(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"name": name, "conf": conf})
}

func (s *Server) handleInterfacePeers(w http.ResponseWriter, r *http.Request) {
	id, ok := s.idOrFail(w, r)
	if !ok {
		return
	}
	peers, err := s.svc.ListPeers(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": peers})
}

// ---------------------------------------------------------------- 节点

func (s *Server) handleListPeers(w http.ResponseWriter, r *http.Request) {
	var ifaceID int64
	if v := r.URL.Query().Get("interface_id"); v != "" {
		if n, err := parseInt(v); err == nil {
			ifaceID = n
		}
	}
	peers, err := s.svc.ListPeers(r.Context(), ifaceID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": peers})
}

func (s *Server) handleGetPeer(w http.ResponseWriter, r *http.Request) {
	id, ok := s.idOrFail(w, r)
	if !ok {
		return
	}
	p, err := s.svc.GetPeer(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) handleCreatePeer(w http.ResponseWriter, r *http.Request) {
	var in service.PeerInput
	if err := decodeBody(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	p, err := s.svc.CreatePeer(r.Context(), in, actorOf(r))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) handleUpdatePeer(w http.ResponseWriter, r *http.Request) {
	id, ok := s.idOrFail(w, r)
	if !ok {
		return
	}
	var in service.PeerInput
	if err := decodeBody(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	p, err := s.svc.UpdatePeer(r.Context(), id, in, actorOf(r))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) handleDeletePeer(w http.ResponseWriter, r *http.Request) {
	id, ok := s.idOrFail(w, r)
	if !ok {
		return
	}
	if err := s.svc.DeletePeer(r.Context(), id, actorOf(r)); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
}

func (s *Server) handleBatchPeers(w http.ResponseWriter, r *http.Request) {
	var req service.BatchPeerRequest
	if err := decodeBody(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	msg, err := s.svc.BatchPeers(r.Context(), req, actorOf(r))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": msg})
}

func (s *Server) handlePeerConfig(w http.ResponseWriter, r *http.Request) {
	id, ok := s.idOrFail(w, r)
	if !ok {
		return
	}
	res, err := s.svc.PeerConfig(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handlePeerSecrets(w http.ResponseWriter, r *http.Request) {
	id, ok := s.idOrFail(w, r)
	if !ok {
		return
	}
	secrets, err := s.svc.RevealPeerSecrets(r.Context(), id, actorOf(r))
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, secrets)
}

func (s *Server) handlePeerHistory(w http.ResponseWriter, r *http.Request) {
	id, ok := s.idOrFail(w, r)
	if !ok {
		return
	}
	p, err := s.svc.GetPeer(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	since := time.Now().Add(-24 * time.Hour)
	if v := r.URL.Query().Get("range"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			since = time.Now().Add(-d)
		}
	}
	points, err := s.svc.PeerHistory(r.Context(), p.InterfaceID, p.PublicKey, since)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"points": points})
}

// ---------------------------------------------------------------- 密钥

func (s *Server) handleKeyPair(w http.ResponseWriter, r *http.Request) {
	out, err := s.svc.GenerateKeypair(r.Context(), actorOf(r))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleKeyPSK(w http.ResponseWriter, r *http.Request) {
	out, err := s.svc.GeneratePSK(r.Context(), actorOf(r))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// ---------------------------------------------------------------- 导入导出

func (s *Server) handleImportConfig(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Text string `json:"text"`
		Name string `json:"name"`
	}
	if err := decodeBody(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if in.Text == "" {
		writeErr(w, http.StatusBadRequest, "配置内容为空")
		return
	}
	it, count, err := s.svc.ImportConf(r.Context(), in.Text, in.Name, actorOf(r))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"interface": it, "peer_count": count})
}

func (s *Server) handleExportAll(w http.ResponseWriter, r *http.Request) {
	raw, filename, err := s.svc.ExportAllZip(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", "attachment; filename="+filename)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

func (s *Server) handleExportInterface(w http.ResponseWriter, r *http.Request) {
	id, ok := s.idOrFail(w, r)
	if !ok {
		return
	}
	filename, conf, err := s.svc.ExportInterface(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename="+filename)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(conf))
}

// idOrFail 解析路径中的 ID，失败时已写出响应。
func (s *Server) idOrFail(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := pathID(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return 0, false
	}
	return id, true
}

func parseInt(v string) (int64, error) {
	var n int64
	for _, c := range v {
		if c < '0' || c > '9' {
			return 0, errBadInt
		}
		n = n*10 + int64(c-'0')
	}
	if v == "" {
		return 0, errBadInt
	}
	return n, nil
}

var errBadInt = errStr("非法数字")

type errStr string

func (e errStr) Error() string { return string(e) }
