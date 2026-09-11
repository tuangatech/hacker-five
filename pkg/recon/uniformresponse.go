package recon

// UniformWallHosts returns every host recon classified as a uniform-response
// wall (LT-59's D6 primitive) as a host→verdict ("waf-block" | "catchall")
// map — the exact shape scanner.Config.UniformWallHosts, and each frontend's
// own per-leaf copy of it (cmd/hackerfive/scan.go, pkg/webui's
// applyTechStackNarrowing, pkg/mcpserver's tools_plan.go/tools_scan.go),
// expect. nil when recon recorded no wall at all.
//
// LT-140: before this, every one of those call sites read the single
// first-host-wins UniformResponse fact, so D6's corpus-skip only ever
// protected one host per multi-host recon run — a second walled host in the
// same run got the full per-target template corpus run against its one
// block/catch-all page, thousands of requests for zero findings. This
// method (backed by ReconResult.UniformResponses, now one fact per host)
// gives every call site the full map in one line instead of each hand-
// rolling a single-entry one from the old pointer field.
func (r *ReconResult) UniformWallHosts() map[string]string {
	if r == nil || len(r.UniformResponses) == 0 {
		return nil
	}
	m := make(map[string]string, len(r.UniformResponses))
	for _, u := range r.UniformResponses {
		m[u.Host] = u.Kind
	}
	return m
}

// UniformResponseForHost returns the uniform-response-wall verdict recon
// recorded for host, or nil if host wasn't classified as one (LT-140).
// Matching is case-insensitive and ignores a leading "www." on either side
// (NormalizeHost — the same normalization addTech's dedup key uses, LT-14),
// since recon may have probed "www.example.com" while a caller building a
// leaf names the bare "example.com".
func (r *ReconResult) UniformResponseForHost(host string) *UniformResponseFact {
	if r == nil {
		return nil
	}
	norm := NormalizeHost(host)
	for i := range r.UniformResponses {
		if NormalizeHost(r.UniformResponses[i].Host) == norm {
			return &r.UniformResponses[i]
		}
	}
	return nil
}
