package main

import (
	"net/http"

	"github.com/alexedwards/scs/v2"
)

type IndexTemplateData struct {
	BasePage
	Flash *Flash
}

type IndexHandler struct {
	PageTemplateRenderer PageTemplateRenderer
	SessionManager       *scs.SessionManager
	NotFoundHandler      http.Handler
}

func (i *IndexHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "" && r.URL.Path != "/" {
		i.NotFoundHandler.ServeHTTP(w, r)
		return
	}

	sessionUser := GetSessionUser(r.Context())
	flash, _ := i.SessionManager.Pop(r.Context(), SessionKeyFlash).(*Flash)
	err := i.PageTemplateRenderer.RenderPageTemplate(w, "index.html", IndexTemplateData{
		BasePage: BasePage{
			SessionUser: sessionUser,
		},
		Flash: flash,
	})
	if err != nil {
		panic(err)
	}
}
