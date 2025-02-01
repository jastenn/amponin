package main

import (
	"html/template"
	"io/fs"
	"net/http"

	"github.com/alexedwards/scs/v2"
)

type IndexTemplateData struct {
	LoginSession *SessionUser
	Flash        *Flash
}

type IndexHandler struct {
	TemplateFS      fs.FS
	SessionManager  *scs.SessionManager
	NotFoundHandler http.Handler

	indexTemplateCache *template.Template
}

func (i *IndexHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sessionUser, _ := GetSessionUser(i.SessionManager, r.Context())
	flash, _ := i.SessionManager.Pop(r.Context(), SessionKeyFlash).(*Flash)

	if r.URL.Path != "" && r.URL.Path != "/" {
		i.NotFoundHandler.ServeHTTP(w, r)
		return
	}

	if i.indexTemplateCache == nil {
		var err error
		i.indexTemplateCache, err = template.ParseFS(i.TemplateFS, "base.html", "index.html")
		if err != nil {
			panic("unable to parse index template: " + err.Error())
		}
	}
	err := ExecuteTemplate(i.indexTemplateCache, w, "base.html", IndexTemplateData{
		LoginSession: sessionUser,
		Flash:        flash,
	})
	if err != nil {
		panic("unable to execute index template: " + err.Error())
	}
}
