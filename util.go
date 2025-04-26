package main

import (
	"bytes"
	"fmt"
	"html/template"
	"net/http"
)

func RenderPage(w http.ResponseWriter, tpl *template.Template, status int, data any) error {
	var b bytes.Buffer
	err := tpl.Execute(&b, data)
	if err != nil {
		return fmt.Errorf("unable to execute template: %w", err)
	}

	w.Write(b.Bytes())

	w.Header().Add("Content-Type", "text/html")
	w.WriteHeader(status)
	return nil
}
