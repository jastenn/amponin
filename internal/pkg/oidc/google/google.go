package google

import (
	"context"
	"errors"
	"strings"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/jastenn/amponin/internal/pkg/oidc"
)

const (
	jwksURL   = "https://www.googleapis.com/oauth2/v3/certs"
	issuerURL = "https://accounts.google.com"
)

// GoogleClaims is the parsed payload of the ID token issued by Google
type GoogleClaims struct {
	ID       string  `json:"sub"`
	Email    string  `json:"email"`
	Verified bool    `json:"email_verified"`
	Picture  *string `json:"picture"`
}

type IDTokenVerifier struct {
	verifier *gooidc.IDTokenVerifier
}

func NewIDTokenVerifier(clientID string) *IDTokenVerifier {
	var skipClientIDCheck bool
	if clientID == "" {
		skipClientIDCheck = true
	}
	googleOIDCConfig := &gooidc.Config{
		SkipClientIDCheck: skipClientIDCheck,
	}
	keySet := gooidc.NewRemoteKeySet(context.Background(), jwksURL)

	return &IDTokenVerifier{
		verifier: gooidc.NewVerifier(issuerURL, keySet, googleOIDCConfig),
	}
}

// VerifyAndParseClaims verifies and parses the Google issued ID token and returns a GoogleClaims.
func (g *IDTokenVerifier) VerifyAndParseClaims(ctx context.Context, rawIDToken string) (GoogleClaims, error) {
	idToken, err := g.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		var tokenExpiredError *gooidc.TokenExpiredError
		switch {
		case strings.Contains(err.Error(), "oidc: malformed jwt"):
			return GoogleClaims{}, oidc.ErrIDTokenInvalid
		case errors.As(err, &tokenExpiredError):
			return GoogleClaims{}, oidc.ErrIDTokenExpired
		}
		return GoogleClaims{}, err
	}

	var claims GoogleClaims
	err = idToken.Claims(&claims)
	if err != nil {
		panic(err)
	}

	return claims, nil
}
