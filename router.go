package main

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func (a *application) router() http.Handler {
	r := chi.NewMux()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Get(
		"/healthcheck",
		(&HealthCheckHandler{environment: a.config.environment}).ServeHTTP,
	)

	r.Mount("/users", NewUsersHandler(a.usersService))

	return r
}
