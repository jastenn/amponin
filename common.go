package main

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"net/http"
	"time"
)

//go:embed templates/* static/*
var embedFS embed.FS

const (
	NanoidGenerator = "ABCDEFGHIJKLMNPQRSTUVWXYZ123456789"

	ClientMessageUnexpectedError = "Unexpected error occurred. Please try again later."

	SessionMaxAgeFlash = time.Minute * 10
	SessionKeyFlash    = "session_flash"
)

const (
	FlashLevelError   = "error"
	FlashLevelWarn    = "warn"
	FlashLevelSuccess = "success"
	FlashLevelInfo    = "info"
)

type Flash struct {
	Level   string
	Message string
}

func RenderPage(w http.ResponseWriter, tpl *template.Template, status int, data any) error {
	var b bytes.Buffer
	err := tpl.ExecuteTemplate(&b, "base.html", data)
	if err != nil {
		return fmt.Errorf("unable to execute template: %w", err)
	}

	w.Header().Add("Content-Type", "text/html")
	w.WriteHeader(status)

	w.Write(b.Bytes())
	return nil
}
