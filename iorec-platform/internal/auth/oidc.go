package auth

import (
	"context"
	"errors"

	"github.com/coreos/go-oidc/v3/oidc"
)

// OIDC verifies tokens issued by an OpenID Connect provider.
type OIDC struct{ v *oidc.IDTokenVerifier }

// NewOIDC discovers the issuer.
func NewOIDC(ctx context.Context, issuer, clientID string) (*OIDC, error) {
	p, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, err
	}
	return &OIDC{v: p.Verifier(&oidc.Config{ClientID: clientID, SkipClientIDCheck: clientID == ""})}, nil
}

// Verify returns email (preferred) or sub.
func (o *OIDC) Verify(ctx context.Context, raw string) (string, error) {
	t, err := o.v.Verify(ctx, raw)
	if err != nil {
		return "", err
	}
	var claims struct {
		Email string `json:"email"`
	}
	_ = t.Claims(&claims)
	if claims.Email != "" {
		return claims.Email, nil
	}
	if t.Subject == "" {
		return "", errors.New("token has no subject")
	}
	return t.Subject, nil
}
