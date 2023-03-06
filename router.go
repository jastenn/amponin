package main

import (
	"net/http"

    "github.com/go-chi/chi/v5"
)

func (a *application) router() http.Handler {
	r := chi.NewMux()

	r.Get(
		"/healthcheck",
		(&HealthCheckHandler{environment: a.config.environment}).ServeHTTP,
	)

	r.Mount("/users", NewUsersHandler(a.googleIDTokenVerifier))

	return r
}
