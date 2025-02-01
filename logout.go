package main

import (
	"log/slog"
	"net/http"

	"github.com/alexedwards/scs/v2"
)

type DoLogout struct {
	Log             *slog.Logger
	SessionManager    *scs.SessionManager
	SuccessRedirect string
}

func (d *DoLogout) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	loginSession := RemoveSessionUser(d.SessionManager, r.Context())
	if loginSession == nil {
		d.Log.Debug("No session user was found. Operation did nothing.")
	}

	d.Log.Debug("User successfully logged out.", "user_id", loginSession.UserID)
	PutSessionFlash(
		d.SessionManager, r.Context(),
		"Successfully logged out.", FlashLevelSuccess,
	)
	http.Redirect(w, r, d.SuccessRedirect, http.StatusSeeOther)
}
