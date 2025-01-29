package main

import (
	"context"
	"errors"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"time"
)

var (
	ErrNoUser = errors.New("no user found")
)

type User struct {
	ID          string
	DisplayName string
	Email       string
	AvatarURL   *string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type LocalAccount struct {
	UserID       string
	PasswordHash []byte
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type AccountSettingsTemplateData struct {
	LoginSession         *LoginSession
	User                 *User
	Focus                string
	GeneralUpdateValues  AccountGeneralUpdateValues
	GeneralUpdateErrors  AccountGeneralUpdateErrors
	EmailUpdateValue     string
	EmailUpdateError     string
	PasswordUpdateValues AccountPasswordUpdateValues
	PasswordUpdateErrors AccountPasswordUpdateErrors
}

type AccountGeneralUpdateValues struct {
	DisplayName string
}

type AccountGeneralUpdateErrors struct {
	DisplayName string
	Avatar      string
}

type AccountPasswordUpdateValues struct {
	CurrentPassword string
	NewPassword     string
	ConfirmPassword string
}

type AccountPasswordUpdateErrors struct {
	CurrentPassword string
	NewPassword     string
	ConfirmPassword string
}

type AccountSettingsHandler struct {
	Log            *slog.Logger
	TemplateFS     fs.FS
	SessionStore   *CookieStore
	UserGetterByID interface {
		GetUserByID(ctx context.Context, userID string) (*User, error)
	}
	LoginRedirectURL string

	accountSettingsTemplateCache *template.Template
}

func (a *AccountSettingsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	focus := r.FormValue("focus")
	loginSession, _ := GetLoginSession(a.SessionStore, w, r)
	if loginSession == nil {
		a.Log.Debug("Unauthenticated user tried account settings.")
		a.SessionStore.SetFlash(w, "Unauthorized. Please log in first.", FlashLevelError)
		http.Redirect(w, r, a.LoginRedirectURL, http.StatusSeeOther)
		return
	}

	user, err := a.UserGetterByID.GetUserByID(r.Context(), loginSession.UserID)
	if err != nil {
		if errors.Is(err, ErrNoUser) {
			a.Log.Debug("User no longer exists.")
			a.SessionStore.SetFlash(w, "Unauthorized. User no longer exists.", FlashLevelError)
			http.Redirect(w, r, a.LoginRedirectURL, http.StatusSeeOther)
			return
		}
		a.Log.Error("Unable to get user by its id.", "reason", err.Error())
		a.RenderPage(w, AccountSettingsTemplateData{
			LoginSession: loginSession,
		})
		return
	}

	a.RenderPage(w, AccountSettingsTemplateData{
		LoginSession: loginSession,
		User:         user,
		Focus:        focus,
	})
}

func (a *AccountSettingsHandler) RenderPage(w http.ResponseWriter, data AccountSettingsTemplateData) {
	if a.accountSettingsTemplateCache == nil {
		var err error
		a.accountSettingsTemplateCache, err = template.ParseFS(a.TemplateFS, "base.html", "account_settings.html")
		if err != nil {
			panic("unable to parse account settings template: " + err.Error())
		}
	}
	err := ExecuteTemplate(a.accountSettingsTemplateCache, w, "base.html", data)
	if err != nil {
		panic("unable to execute accoutn settings template: " + err.Error())
	}
}
