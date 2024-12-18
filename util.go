package main

import (
	"bytes"
	"fmt"
	"html/template"
	"io"
	"net/http"
)

func ExecuteTemplate(tpl *template.Template, w http.ResponseWriter, name string, data any) error {
	var b bytes.Buffer
	err := tpl.ExecuteTemplate(&b, name, data)
	if err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}

	_, err = io.Copy(w, &b)
	if err != nil {
		return fmt.Errorf("failed to write template: %w", err)
	}

	return nil
}
