package main

import (
	"html/template"
	"io/fs"
	"net/http"
)

type IndexTemplateData struct {
	LoginSession *LoginSession
	Flash        *Flash
}

type IndexHandler struct {
	NotFoundHandler http.Handler
	TemplateFS      fs.FS
	SessionStore    *CookieStore

	indexTemplateCache *template.Template
}

func (i *IndexHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	flash, _ := i.SessionStore.Flash(w, r)
	loginSession, _ := GetLoginSession(i.SessionStore, w, r)
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
		LoginSession: loginSession,
		Flash: flash,
	})
	if err != nil {
		panic("unable to execute index template: " + err.Error())
	}
}
