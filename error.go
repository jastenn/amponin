package main

import (
	"net/http"
)

type NotFoundHandler struct {
	SessionStore *CookieSessionStore
}

func (n *NotFoundHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var loginSessionData *loginSession
	n.SessionStore.Decode(r, sessionKeyLoginSession, &loginSessionData)
	renderErrorPage(w, errorPageData{
		basePageData: basePageData{
			LoginSession: loginSessionData,
		},
		Status:  http.StatusNotFound,
		Message: "404 Page Not Found.",
	})
}
