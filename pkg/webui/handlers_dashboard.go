package webui

import "net/http"

// dashboardRecentLimit caps how many jobs the Dashboard's "Recent Scans"
// list shows — the full list stays available at /scans (scanHistory).
const dashboardRecentLimit = 10

func (h *handlers) dashboard(w http.ResponseWriter, r *http.Request) {
	all := h.store.List()
	data := DashboardData{HasMore: len(all) > dashboardRecentLimit}
	if len(all) > dashboardRecentLimit {
		data.RecentJobs = all[:dashboardRecentLimit]
	} else {
		data.RecentJobs = all
	}
	executeTemplate(w, h.tmpl, "dashboard.html", data)
}

func (h *handlers) scanHistory(w http.ResponseWriter, r *http.Request) {
	executeTemplate(w, h.tmpl, "scan_history.html", ScanHistoryData{Jobs: h.store.List()})
}
