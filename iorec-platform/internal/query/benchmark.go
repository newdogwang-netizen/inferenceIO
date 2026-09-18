package query

import (
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/heidihealth/iorec-platform/internal/auth"
	"github.com/heidihealth/iorec-platform/internal/httpapi"
)

// A result is an explicitly attributed external assertion. Only its digest,
// bounded identifiers and scalar score are accepted; never verifier logs.
type benchmarkResult struct {
	Framework string   `json:"framework"`
	Task      string   `json:"task"`
	Trial     string   `json:"trial"`
	Model     string   `json:"model"`
	Agent     string   `json:"agent"`
	Status    string   `json:"status"`
	Reward    *float64 `json:"reward"`
	SHA256    string   `json:"artifact_sha256"`
}

var benchmarkIdentifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.:/@+~-]{0,255}$`)
var benchmarkDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

func (b benchmarkResult) valid() bool {
	if b.Framework != "harbor" || !benchmarkDigest.MatchString(b.SHA256) {
		return false
	}
	for _, value := range []string{b.Task, b.Trial, b.Model, b.Agent} {
		if !benchmarkIdentifier.MatchString(value) {
			return false
		}
	}
	if b.Status != "completed" && b.Status != "error" && b.Status != "timeout" {
		return false
	}
	if b.Reward != nil && (b.Status != "completed" || math.IsNaN(*b.Reward) || math.IsInf(*b.Reward, 0)) {
		return false
	}
	return true
}

// PutBenchmarkResult is immutable and retry-safe. A changed result is rejected
// rather than silently replacing the artifact that an operator attested to.
func (s *Service) PutBenchmarkResult(w http.ResponseWriter, r *http.Request) {
	p, err := httpapi.RequireUser(r, auth.RoleOperator)
	if err != nil {
		httpapi.WriteError(w, r, err)
		return
	}
	var body benchmarkResult
	if err := httpapi.DecodeJSON(r, &body, 4096); err != nil {
		httpapi.WriteError(w, r, err)
		return
	}
	if !body.valid() {
		httpapi.WriteError(w, r, httpapi.E(400, "invalid_benchmark_result", "expected bounded Harbor identifiers, status, optional finite reward and artifact SHA-256"))
		return
	}
	id := pathParam(r, "id")
	canonical, _ := json.Marshal(body)
	var result json.RawMessage
	created := false
	err = s.DB.Tx(r.Context(), func(tx pgx.Tx) error {
		var existing json.RawMessage
		err := tx.QueryRow(r.Context(), `select benchmark_result from capture_runs where id=$1 and project_id=$2 and state='active' for update`, id, p.ProjectID).Scan(&existing)
		if errors.Is(err, pgx.ErrNoRows) {
			return httpapi.E(404, "not_found", "no active capture run")
		}
		if err != nil {
			return err
		}
		if len(existing) > 0 {
			var previous struct {
				Result benchmarkResult `json:"result"`
			}
			if err := json.Unmarshal(existing, &previous); err != nil {
				return err
			}
			old, _ := json.Marshal(previous.Result)
			if string(old) != string(canonical) {
				return httpapi.E(409, "benchmark_conflict", "a different benchmark result is already attached")
			}
			result = existing
			return nil
		}
		result, err = json.Marshal(map[string]any{"result": body, "provenance": "operator_reported_not_recomputed", "reported_by": p.Subject, "reported_at": time.Now().UTC()})
		if err != nil {
			return err
		}
		if _, err := tx.Exec(r.Context(), `update capture_runs set benchmark_result=$3 where id=$1 and project_id=$2`, id, p.ProjectID, result); err != nil {
			return err
		}
		if _, err := tx.Exec(r.Context(), `insert into audit_log(project_id,subject,action,entity_type,entity_id,detail) values($1,$2,'benchmark.attach','capture_run',$3,$4)`, p.ProjectID, p.Subject, id, map[string]any{"artifact_sha256": body.SHA256, "framework": body.Framework}); err != nil {
			return err
		}
		created = true
		return nil
	})
	if err != nil {
		httpapi.WriteError(w, r, err)
		return
	}
	code := http.StatusOK
	if created {
		code = http.StatusCreated
	}
	httpapi.WriteJSON(w, code, map[string]any{"created": created, "benchmark_result": result})
}
