// Package auth resolves bearer credentials to a Principal (collector or user)
// and injects tenant/project scope. Tenant identity always comes from the
// credential, never from request payloads (platform/10 §3).
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Kinds and roles.
const (
	KindCollector = "collector"
	KindUser      = "user"

	RoleViewer   = "viewer"
	RoleReviewer = "reviewer"
	RoleOperator = "operator"
	RoleAdmin    = "admin"
)

var roleRank = map[string]int{RoleViewer: 1, RoleReviewer: 2, RoleOperator: 3, RoleAdmin: 4}

// Principal is the authenticated caller.
type Principal struct {
	Kind        string
	TenantID    uuid.UUID
	ProjectID   uuid.UUID
	CollectorID uuid.UUID // collectors only
	Subject     string    // users: email/sub; collectors: collector id
	Role        string    // users only
}

// HasRole reports whether the principal meets the minimum role.
func (p Principal) HasRole(min string) bool {
	if p.Kind != KindUser {
		return false
	}
	return roleRank[p.Role] >= roleRank[min]
}

type ctxKey struct{}

// FromContext returns the principal.
func FromContext(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(ctxKey{}).(Principal)
	return p, ok
}

// WithPrincipal stores a principal (tests, internal calls).
func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, ctxKey{}, p)
}

// Config controls user authentication.
type Config struct {
	// Mode: "dev" trusts X-Dev-User / anonymous as admin of the default project; "token" requires static user tokens; "oidc" verifies JWTs.
	Mode             string
	DefaultTenantID  uuid.UUID
	DefaultProjectID uuid.UUID
	// UserTokens maps static bearer tokens to "subject:role" (token mode / dev extra).
	UserTokens map[string]string
	// OIDC verifier (optional).
	OIDC OIDCVerifier
}

// OIDCVerifier validates an ID/access token and returns the subject (email preferred).
type OIDCVerifier interface {
	Verify(ctx context.Context, rawToken string) (subject string, err error)
}

// Authenticator resolves tokens.
type Authenticator struct {
	Pool *pgxpool.Pool
	Cfg  Config
}

// HashToken returns the storage hash for a secret.
func HashToken(tok string) []byte {
	h := sha256.Sum256([]byte(tok))
	return h[:]
}

// NewToken generates a random URL-safe secret with the given prefix.
func NewToken(prefix string) string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return prefix + base64.RawURLEncoding.EncodeToString(b)
}

// ErrUnauthorized is returned for unknown credentials.
var ErrUnauthorized = errors.New("unauthorized")

// Resolve maps a request to a principal.
func (a *Authenticator) Resolve(r *http.Request) (Principal, error) {
	ctx := r.Context()
	tok := bearer(r)
	if tok != "" {
		// 1. collector session token
		if p, ok, err := a.collectorSession(ctx, tok); err != nil {
			return Principal{}, err
		} else if ok {
			return p, nil
		}
		// 2. project token (registration / direct upload)
		if p, ok, err := a.projectToken(ctx, tok); err != nil {
			return Principal{}, err
		} else if ok {
			return p, nil
		}
		// 3. static user token
		if v, ok := a.Cfg.UserTokens[tok]; ok {
			subj, role, _ := strings.Cut(v, ":")
			if role == "" {
				role = RoleViewer
			}
			return a.user(ctx, subj, role)
		}
		// 4. OIDC
		if a.Cfg.OIDC != nil {
			subj, err := a.Cfg.OIDC.Verify(ctx, tok)
			if err == nil {
				return a.user(ctx, subj, "")
			}
		}
	}
	if a.Cfg.Mode == "dev" {
		subj := r.Header.Get("X-Dev-User")
		if subj == "" {
			subj = "dev@local"
		}
		role := r.Header.Get("X-Dev-Role")
		if role == "" {
			role = RoleAdmin
		}
		return a.user(ctx, subj, role)
	}
	return Principal{}, ErrUnauthorized
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "Bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

func (a *Authenticator) collectorSession(ctx context.Context, tok string) (Principal, bool, error) {
	if !strings.HasPrefix(tok, "iorc_") {
		return Principal{}, false, nil
	}
	var p Principal
	var exp *time.Time
	err := a.Pool.QueryRow(ctx, `select c.id, c.project_id, p.tenant_id, c.session_expires_at from collectors c join projects p on p.id=c.project_id where c.session_token_hash=$1 and c.status <> 'revoked'`, HashToken(tok)).
		Scan(&p.CollectorID, &p.ProjectID, &p.TenantID, &exp)
	if errors.Is(err, pgx.ErrNoRows) {
		return Principal{}, false, nil
	}
	if err != nil {
		return Principal{}, false, err
	}
	if exp != nil && exp.Before(time.Now()) {
		return Principal{}, false, nil
	}
	p.Kind = KindCollector
	p.Subject = p.CollectorID.String()
	return p, true, nil
}

func (a *Authenticator) projectToken(ctx context.Context, tok string) (Principal, bool, error) {
	if !strings.HasPrefix(tok, "iorp_") {
		return Principal{}, false, nil
	}
	var p Principal
	err := a.Pool.QueryRow(ctx, `select t.project_id, p.tenant_id from project_tokens t join projects p on p.id=t.project_id where t.token_hash=$1 and t.revoked_at is null`, HashToken(tok)).
		Scan(&p.ProjectID, &p.TenantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Principal{}, false, nil
	}
	if err != nil {
		return Principal{}, false, err
	}
	p.Kind = KindCollector // project-scoped machine credential; CollectorID zero until registered
	p.Subject = "project-token"
	return p, true, nil
}

func (a *Authenticator) user(ctx context.Context, subject, role string) (Principal, error) {
	p := Principal{Kind: KindUser, Subject: subject, TenantID: a.Cfg.DefaultTenantID, ProjectID: a.Cfg.DefaultProjectID, Role: role}
	// role from table overrides when present
	var dbRole string
	err := a.Pool.QueryRow(ctx, `select role from user_roles where project_id=$1 and subject=$2`, p.ProjectID, subject).Scan(&dbRole)
	if err == nil {
		p.Role = dbRole
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return Principal{}, err
	}
	if p.Role == "" {
		p.Role = RoleViewer
	}
	return p, nil
}

// ConstantTimeEqual compares secrets.
func ConstantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// Bootstrap ensures the default tenant/project exist and optionally installs a project token.
func Bootstrap(ctx context.Context, pool *pgxpool.Pool, cfg Config, projectToken string) error {
	if _, err := pool.Exec(ctx, `insert into tenants(id,name) values($1,'default') on conflict do nothing`, cfg.DefaultTenantID); err != nil {
		return err
	}
	if _, err := pool.Exec(ctx, `insert into projects(id,tenant_id,name) values($1,$2,'default') on conflict do nothing`, cfg.DefaultProjectID, cfg.DefaultTenantID); err != nil {
		return err
	}
	if projectToken != "" {
		if _, err := pool.Exec(ctx, `insert into project_tokens(id,project_id,token_hash,label) values($1,$2,$3,'bootstrap') on conflict (token_hash) do nothing`, uuid.New(), cfg.DefaultProjectID, HashToken(projectToken)); err != nil {
			return err
		}
	}
	return nil
}
