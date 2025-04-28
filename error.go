package main

import (
	"net/http"
)

type NotFoundHandler struct{}

func (n *NotFoundHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	renderErrorPage(w, errorPageData{
		Status:  http.StatusNotFound,
		Message: "404 Page Not Found.",
	})
}
