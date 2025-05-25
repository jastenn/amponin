package main

import (
	"embed"
	"html/template"
	"net/http"
	"time"
)

//go:embed templates/* static/*
var embedFS embed.FS

const (
	nanoidGenerator = "ABCDEFGHIJKLMNPQRSTUVWXYZ123456789"

	clientMessageUnexpectedError = "Unexpected error occurred. Please try again later."

	flashMaxAge     = time.Minute * 10
	sessionKeyFlash = "session_flash"
)

const (
	flashLevelError   = "error"
	flashLevelWarn    = "warn"
	flashLevelSuccess = "success"
	flashLevelInfo    = "info"
)

type flash struct {
	Level   string
	Message string
}

type basePageData struct {
	LoginSession *loginSession
}

var errorTemplate = template.Must(template.ParseFS(embedFS, "templates/pages/base.html", "templates/pages/error.html"))

type errorPageData struct {
	Status  int
	Message string
	basePageData
}

func renderErrorPage(w http.ResponseWriter, data errorPageData) {
	err := RenderPage(w, errorTemplate, data.Status, data)
	if err != nil {
		panic(err)
	}
}

type ImageProvider string

const (
	ImageProviderLocal   ImageProvider = "local"
	ImageProviderForeign ImageProvider = "foreign"
)

type Image struct {
	URL      string
	Provider ImageProvider
}
