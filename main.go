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

	http.Handle("/", &IndexHandler{})
	// embedFS contains a static directory which hosts all the static files
	// needed to be served.
	http.Handle("GET /static/", http.FileServerFS(embedFS))

	log.Info("Server running.", "address", *address)
	http.ListenAndServe(*address, nil)
}

type IndexHandler struct{}

var indexTemplate = template.Must(template.ParseFS(embedFS, "templates/index.html"))

func (i *IndexHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	indexTemplate.Execute(w, nil)
}
