package main

import (
	"errors"
	"log/slog"
	"net/http"
)

type DoLogout struct {
	Log             *slog.Logger
	SessionStore    *CookieStore
	SuccessRedirect string
}

func (d *DoLogout) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	loginSession, err := RemoveLoginSession(d.SessionStore, w, r)
	if err != nil {
		if errors.Is(err, ErrNoSessionData) {
			d.Log.Debug("User is not logged in.")
			http.Redirect(w, r, d.SuccessRedirect, http.StatusSeeOther)
			return
		}

		d.Log.Error("Failed to remove login session", "reason", err.Error())
		d.SessionStore.SetFlash(w, "Something went wrong.", FlashLevelError)
		http.Redirect(w, r, d.SuccessRedirect, http.StatusSeeOther)
		return
	}

	d.Log.Debug("User successfully logged out.", "user_id", loginSession.UserID)
	d.SessionStore.SetFlash(w, "Successfully logged out.", FlashLevelSuccess)
	http.Redirect(w, r, d.SuccessRedirect, http.StatusSeeOther)
}
