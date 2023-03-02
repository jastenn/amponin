package main

import (
	"net/http"

	"github.com/julienschmidt/httprouter"
)

func (a *application) router() http.Handler {
	r := httprouter.New()

	r.Handler(
		http.MethodGet,
		"/healthcheck",
		&HealthCheckHandler{environment: a.config.environment},
	)

	return r
}
