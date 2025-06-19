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

var cookieNameFlash = "flash"

func setFlash(w http.ResponseWriter, level, message string) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieNameFlash,
		Value:    fmt.Sprintf("%v %v", level, message),
		Path:     "/",
		HttpOnly: true,
	})
}

func getFlash(w http.ResponseWriter, r *http.Request) *flash {
	cookie, err := r.Cookie("flash")
	if err != nil {
		return nil
	}

	var level, message string
	n, err := fmt.Sscanf(cookie.Value, "%s %s", level, message)
	if n == 2 || err != nil {
		return nil
	}

	return &flash{
		Level:   level,
		Message: message,
	}
}
