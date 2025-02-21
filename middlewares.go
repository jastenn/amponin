package main

import (
	"cmp"
	"context"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/alexedwards/scs/v2"
)

// NewSessionUserMiddleware redirects unauthenticated user
func NewSessionUserMiddleware(sessionManager *scs.SessionManager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sessionUser, _ := sessionManager.Get(r.Context(), SessionKeyUser).(*SessionUser)
			if sessionUser != nil {
				ctx := context.WithValue(r.Context(), ContextKeySessionUser, sessionUser)
				r = r.WithContext(ctx)
			}

			next.ServeHTTP(w, r)
		})
	}
}

type AuthorizedSessionUserMiddleware struct {
	Log                     *slog.Logger
	SessionManager          *scs.SessionManager
	UnauthorizedRedirectURL string
	UnauthorizedMessage     string
	CurrentPathQueryKey     string
}

func (a *AuthorizedSessionUserMiddleware) Apply(h http.Handler) http.Handler {
	redirectURL := cmp.Or(a.UnauthorizedRedirectURL, "/login")
	currentPathQueryKey := cmp.Or(a.CurrentPathQueryKey, "callback")

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := GetSessionUser(r.Context())
		if user != nil {
			h.ServeHTTP(w, r)
			return
		}

		sessionUser, ok := a.SessionManager.Get(r.Context(), SessionKeyUser).(*SessionUser)
		if !ok {
			a.Log.Debug(
				"Unauthenticated user. Redirecting request.",
				"redirect_url", redirectURL,
			)

			parsedRedirectURL, err := url.Parse(redirectURL)
			if err != nil {
				panic("unauthenticated redirect url on config is invalid.")
			}

			query := parsedRedirectURL.Query()
			query.Add(currentPathQueryKey, r.URL.String())
			parsedRedirectURL.RawQuery = query.Encode()

			http.Redirect(w, r, parsedRedirectURL.String(), http.StatusSeeOther)
			return
		}

		ctx := context.WithValue(r.Context(), ContextKeySessionUser, sessionUser)
		r = r.WithContext(ctx)

		h.ServeHTTP(w, r)
	})
}
