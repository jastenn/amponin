package main

import (
	"html/template"
	"log/slog"
	"net/http"
)

type IndexHandler struct {
	Log             *slog.Logger
	NotFoundHandler http.Handler
}

var indexTemplate = template.Must(template.ParseFS(embedFS, "templates/base.html", "templates/index.html"))

func (i *IndexHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		i.Log.Debug("Page not found.", "path", r.URL.Path)
		i.NotFoundHandler.ServeHTTP(w, r)
		return
	}
	err := RenderPage(w, indexTemplate, http.StatusOK, nil)
	if err != nil {
		i.Log.Error("Unexpected error occured.", "error", err)
		RenderErrorPage(w, http.StatusInternalServerError, "Something went wrong. Please try again later.")
		return
	}
}
