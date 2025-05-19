package main

import (
	"bytes"
	"fmt"
	"html/template"
	"net/http"
)

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

func NewFlash(level, message string) *flash {
	return &flash{
		Level:   level,
		Message: message,
	}
}
