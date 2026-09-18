package query

import (
	"net/http"

	"github.com/heidihealth/iorec-platform/internal/auth"
	"github.com/heidihealth/iorec-platform/internal/httpapi"
)

// SystemHealth exposes liveness without worker hostnames or other projects'
// workloads. A fresh heartbeat does not certify job correctness or queue drain.
func (s *Service) SystemHealth(w http.ResponseWriter, r *http.Request) {
	p, err := httpapi.RequireUser(r, auth.RoleOperator)
	if err != nil {
		httpapi.WriteError(w, r, err)
		return
	}
	pools, err := s.list(r.Context(), `select required.type,count(w.owner) as workers from
 (values ('decode'),('assemble'),('normalize'),('resolve'),('transport_audit'),('coverage'),('rules'),('export')) as required(type)
 left join worker_heartbeats w on w.last_seen_at > now()-interval '45 seconds' and coalesce((w.pools->>required.type)::int,0)>0
 group by required.type order by required.type`)
	if err != nil {
		httpapi.WriteError(w, r, err)
		return
	}
	queue, err := s.list(r.Context(), `select status,count(*) as jobs from processing_jobs where project_id=$1 group by status order by status`, p.ProjectID)
	if err != nil {
		httpapi.WriteError(w, r, err)
		return
	}
	ok := true
	for _, pool := range pools {
		if pool["workers"].(int64) == 0 {
			ok = false
		}
	}
	code := http.StatusOK
	if !ok {
		code = http.StatusServiceUnavailable
	}
	w.Header().Set("Cache-Control", "no-store")
	httpapi.WriteJSON(w, code, map[string]any{"ok": ok, "api_database": "reachable", "worker_pools": pools, "heartbeat_max_age_seconds": 45, "queue": queue, "scope": "worker_process_database_liveness_not_job_correctness_or_queue_drain"})
}
