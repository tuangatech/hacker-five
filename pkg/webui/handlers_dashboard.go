package webui

import "net/http"

func (h *handlers) scanHistory(w http.ResponseWriter, r *http.Request) {
	executeTemplate(w, h.tmpl, "scan_history.html", ScanHistoryData{Jobs: h.store.List()})
}
