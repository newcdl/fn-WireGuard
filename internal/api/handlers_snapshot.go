package api

import (
	"net/http"
)

// ---------------------------------------------------------------- 配置快照与一键回滚

// handleListSnapshots 列出全部配置快照。
//
// 快照是「关键配置改动前自动留下的存档」，与用户主动创建的备份是两回事，
// 因此单独一个列表：备份页只显示 manual/imported，这里只显示 auto。
func (s *Server) handleListSnapshots(w http.ResponseWriter, r *http.Request) {
	items, err := s.svc.ListSnapshots(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items": items,
		"keep":  s.svc.SnapshotKeep(r.Context()),
	})
}

// handleCreateSnapshot 手动留一份快照。
func (s *Server) handleCreateSnapshot(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Note string `json:"note"`
	}
	if err := decodeBody(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	rec, err := s.svc.CreateSnapshot(r.Context(), in.Note, actorOf(r))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if rec == nil {
		// 内容与最近一份快照一致。不重复留档，但要如实告诉用户「这一次没留下新的」，
		// 否则用户以为存了、到时候在列表里找不到，比直接说清楚糟得多。
		writeJSON(w, http.StatusOK, map[string]any{
			"created": false,
			"message": "当前配置与最近一份快照完全一致，未重复留档",
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"created": true, "item": rec})
}

// handleSnapshotDiff 查看某份快照与当前配置的差异。
func (s *Server) handleSnapshotDiff(w http.ResponseWriter, r *http.Request) {
	id, ok := s.idOrFail(w, r)
	if !ok {
		return
	}
	diff, err := s.svc.SnapshotDiff(r.Context(), s.shareDir, id)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, diff)
}

// handleRollbackSnapshot 一键回滚到某份快照。
//
// 回滚前会自动为当前状态留一份快照，回滚后立即收敛内核态；
// 收敛失败时返回明确错误，不会静默当作成功。
func (s *Server) handleRollbackSnapshot(w http.ResponseWriter, r *http.Request) {
	id, ok := s.idOrFail(w, r)
	if !ok {
		return
	}
	n, err := s.svc.RollbackSnapshot(r.Context(), s.shareDir, id, actorOf(r))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"restored_interfaces": n})
}

// handleDeleteSnapshot 删除一份快照。
func (s *Server) handleDeleteSnapshot(w http.ResponseWriter, r *http.Request) {
	id, ok := s.idOrFail(w, r)
	if !ok {
		return
	}
	if err := s.svc.DeleteSnapshot(r.Context(), s.shareDir, id, actorOf(r)); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
}
