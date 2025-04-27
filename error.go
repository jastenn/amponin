package main

import (
	"html/template"
	"net/http"
)

type NotFoundHandler struct{}

func (n *NotFoundHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	RenderErrorPage(w, http.StatusNotFound, "404 Page Not Found.")
}

var errorTemplate = template.Must(template.ParseFS(embedFS, "templates/base.html", "templates/error.html"))

type ErrorPageData struct {
	Status  int
	Message string
}

func RenderErrorPage(w http.ResponseWriter, status int, message string) {
	err := RenderPage(w, errorTemplate, status, ErrorPageData{
		Status:  status,
		Message: message,
	})
	if err != nil {
		panic(err)
	}
}
