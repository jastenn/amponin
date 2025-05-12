package main

import (
	"html/template"
	"log/slog"
	"net/http"
)

type IndexHandler struct {
	Log             *slog.Logger
	SessionStore    *CookieSessionStore
	NotFoundHandler http.Handler
}

var indexTemplate = template.Must(template.ParseFS(embedFS, "templates/pages/index.html", "templates/pages/base.html"))

type indexPageData struct {
	Flash *flash
	basePageData
}

func (i *IndexHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var loginSession *loginSession
	i.SessionStore.Decode(r, sessionKeyLoginSession, &loginSession)

	var flash *flash
	i.SessionStore.DecodeAndRemove(w, r, sessionKeyFlash, &flash)

	if r.URL.Path != "/" {
		i.Log.Debug("Page not found.", "path", r.URL.Path)
		i.NotFoundHandler.ServeHTTP(w, r)
		return
	}
	err := RenderPage(w, indexTemplate, http.StatusOK, &indexPageData{
		basePageData: basePageData{
			LoginSession: loginSession,
		},
		Flash: flash,
	})
	if err != nil {
		i.Log.Error("Unexpected error occured.", "error", err)
		renderErrorPage(w, errorPageData{
			Status:  http.StatusInternalServerError,
			Message: "Something went wrong. Please try again later.",
		})
		return
	}
}
