package main

import (
	"embed"
	"flag"
	"html/template"
	"log/slog"
	"net/http"
	"os"
)

//go:embed templates/* static/*
var embedFS embed.FS

func main() {
	address := flag.String("address", ":8080", "network address to run on")

	log := slog.New(slog.NewTextHandler(os.Stdout, nil))

	http.Handle("/", &IndexHandler{
		Log:             log,
		NotFoundHandler: &NotFoundHandler{},
	})
	// embedFS contains a static directory which hosts all the static files
	// needed to be served.
	http.Handle("GET /static/", http.FileServerFS(embedFS))

	log.Info("Server running.", "address", *address)
	http.ListenAndServe(*address, nil)
}

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
