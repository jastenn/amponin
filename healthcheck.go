package main

import "net/http"

type HealthCheckHandler struct {
	environment string
}

func (h *HealthCheckHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := writeJSON(
		w, http.StatusOK, nil,
		H{
			"status":      "ok",
			"environment": h.environment,
		},
	)
	if err != nil {
		panic(err)
	}
}
