package main

import (
	"bytes"
	"context"
	"errors"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/alexedwards/scs/v2"
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
	Flash                *Flash
	LoginSession         *SessionUser
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

type UserGetterByID interface {
	GetUserByID(ctx context.Context, userID string) (*User, error)
}

type AccountSettingsHandler struct {
	Log              *slog.Logger
	TemplateFS       fs.FS
	SessionManager   *scs.SessionManager
	UserGetterByID   UserGetterByID
	LoginRedirectURL string

	accountSettingsTemplateCache *template.Template
}

func (a *AccountSettingsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	focus := r.FormValue("focus")
	loginSession, _ := GetSessionUser(a.SessionManager, r.Context())
	if loginSession == nil {
		a.Log.Debug("Unauthenticated user tried account settings.")
		PutSessionFlash(a.SessionManager, r.Context(),
			"Unauthorized. Please log in first.", FlashLevelError)
		http.Redirect(w, r, a.LoginRedirectURL, http.StatusSeeOther)
		return
	}

	user, err := a.UserGetterByID.GetUserByID(r.Context(), loginSession.UserID)
	if err != nil {
		if errors.Is(err, ErrNoUser) {
			a.Log.Debug("User no longer exists.")
			PutSessionFlash(a.SessionManager, r.Context(),
				"Unauthorized. User no longer exists.", FlashLevelError)
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

type UserInfoUpdate struct {
	Avatar      *string
	DisplayName *string
	Email       *string
}

type DoAccountSettingsHandler struct {
	Log             *slog.Logger
	TemplateFS      fs.FS
	SessionStore    *scs.SessionManager
	FileStore       FileStore
	UserGetterByID  UserGetterByID
	UserInfoUpdater interface {
		UpdateUserInfo(ctx context.Context, userID string, data UserInfoUpdate) (*User, error)
	}
	UnauthenticatedRedirectURL string
	SuccessRedirectURL         string

	accountSettingsTemplateCache *template.Template
}

func (d *DoAccountSettingsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	loginSession, _ := GetSessionUser(d.SessionStore, r.Context())
	if loginSession == nil {
		d.Log.Debug("User unauthenticated. The request was redirected to UnauthenticatedRedirectURL.")
		PutSessionFlash(d.SessionStore, r.Context(), "Please log in first.", FlashLevelError)
		return
	}

	user, err := d.UserGetterByID.GetUserByID(r.Context(), loginSession.UserID)
	if err != nil {
		if errors.Is(err, ErrNoUser) {
			RemoveSessionUser(d.SessionStore, r.Context())
			d.Log.Debug("User no longer exists. The request was redirected to UnauthenticatedRedirectURL.")
			http.Redirect(w, r, d.UnauthenticatedRedirectURL, http.StatusSeeOther)
			return
		}

		d.Log.Error("Unexpected error while parsing avatar.", "error", err.Error())
		d.RenderPage(w, AccountSettingsTemplateData{
			Flash: &Flash{
				Level:   FlashLevelError,
				Message: "Unexpected error occurred. Please try again later.",
			},
		})
		return
	}

	update := r.FormValue("update")
	if update == "general" {
		d.HandleAccountGeneralUpdate(w, r, loginSession, user)
		return
	}
}

func (d *DoAccountSettingsHandler) HandleAccountGeneralUpdate(w http.ResponseWriter, r *http.Request, loginSession *SessionUser, user *User) {
	var avatar *string
	var displayName *string
	var fieldErrors AccountGeneralUpdateErrors
	if f, fheader, err := r.FormFile("avatar"); !errors.Is(err, http.ErrMissingFile) {
		if err != nil {
			d.Log.Error("Unexpected error while parsing avatar.", "error", err.Error())
			d.RenderPage(w, AccountSettingsTemplateData{
				User:         user,
				LoginSession: loginSession,
				Flash: &Flash{
					Level:   FlashLevelError,
					Message: "Unexpected error occurred. Please try again later.",
				},
			})
			return

		}

		b, err := io.ReadAll(f)
		if err != nil {
			d.Log.Error("Unexpected error while parsing avatar.", "error", err.Error())
			d.RenderPage(w, AccountSettingsTemplateData{
				User:         user,
				LoginSession: loginSession,
				Flash: &Flash{
					Level:   FlashLevelError,
					Message: "Unexpected error occurred. Please try again later.",
				},
			})
			return
		}
		fileType := http.DetectContentType(b)
		xfileType := strings.Split(fileType, "/")
		if xfileType[0] == "image" {
			fileURL, err := d.FileStore.Save("/users/avatar/"+fheader.Filename, bytes.NewBuffer(b))
			if err != nil {
				d.Log.Error("Unexpected error while parsing avatar.", "error", err.Error())
				d.RenderPage(w, AccountSettingsTemplateData{
					User:         user,
					LoginSession: loginSession,
					Flash: &Flash{
						Level:   FlashLevelError,
						Message: "Unexpected error occurred. Please try again later.",
					},
				})
				return
			}

			avatar = &fileURL
		} else {
			fieldErrors.Avatar = "Invalid file type."
		}

	}

	if v := r.FormValue("display-name"); v != "" {
		if l := len(v); l == 1 {
			fieldErrors.DisplayName = "Value is too short."
		} else if l > 16 {
			fieldErrors.DisplayName = "Value is too long. It must not exceed 16 characters long"
		} else {
			displayName = &v
		}
	}

	if fieldErrors.Avatar != "" || fieldErrors.DisplayName != "" {
		d.Log.Debug("General account info update failed validation.", "field_errors", fieldErrors)
		d.RenderPage(w, AccountSettingsTemplateData{
			LoginSession: loginSession,
			Focus:        "general",
			User:         user,
			GeneralUpdateValues: AccountGeneralUpdateValues{
				DisplayName: r.FormValue("display-name"),
			},
			GeneralUpdateErrors: fieldErrors,
		})
		return
	}

	user, err := d.UserInfoUpdater.UpdateUserInfo(r.Context(), loginSession.UserID, UserInfoUpdate{
		Avatar:      avatar,
		DisplayName: displayName,
	})
	if err != nil {
		if errors.Is(err, ErrNoUser) {
			RemoveSessionUser(d.SessionStore, r.Context())
		}

		d.Log.Error("Unexpected error while updating user info", "reason", err)
		d.RenderPage(w, AccountSettingsTemplateData{
			User:         user,
			LoginSession: loginSession,
			Flash: &Flash{
				Level:   FlashLevelError,
				Message: "Unexpected error occurred. Please try again later.",
			},
		})
		return
	}

	loginSession.AvatarURL = user.AvatarURL
	loginSession.DisplayName = user.DisplayName
	PutSessionUser(d.SessionStore, r.Context(), loginSession)
	PutSessionFlash(d.SessionStore, r.Context(),
		"General Infomation was successfully updated.", FlashLevelSuccess)
	http.Redirect(w, r, d.SuccessRedirectURL, http.StatusSeeOther)
}

func (a *DoAccountSettingsHandler) RenderPage(w http.ResponseWriter, data AccountSettingsTemplateData) {
	if a.accountSettingsTemplateCache == nil {
		var err error
		a.accountSettingsTemplateCache, err = template.ParseFS(a.TemplateFS, "base.html", "account_settings.html")
		if err != nil {
			panic("unable to parse account settings template: " + err.Error())
		}
	}
	err := ExecuteTemplate(a.accountSettingsTemplateCache, w, "base.html", data)
	if err != nil {
		panic("unable to execute account settings template: " + err.Error())
	}
}
