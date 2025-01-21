package main

import (
	"context"
	"errors"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"net/mail"
	"time"

	"golang.org/x/crypto/bcrypt"
)

var (
	SessionKeyLoginSession = "login_session"
)

type LoginSession struct {
	UserID      string
	DisplayName string
	Avatar      *string
}

type LoginTemplateData struct {
	LoginSession *LoginSession
	Flash        *Flash
	CallbackURL  string
	Values       LoginValues
	Errors       LoginErrors
}

type LoginValues struct {
	Email    string
	Password string
}

type LoginErrors struct {
	Email    string
	Password string
}

type LoginHandler struct {
	Log                *slog.Logger
	TemplateFS         fs.FS
	SessionStore       *CookieStore
	SuccessRedirectURL string

	loginTemplateCache *template.Template
}

func (l *LoginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	callbackURL := r.FormValue("callback")
	flash, _ := l.SessionStore.Flash(w, r)
	loginSession, _ := GetLoginSession(l.SessionStore, w, r)
	if loginSession != nil {
		l.Log.Debug("User is already logged in.", "user_id", loginSession.UserID)
		l.SessionStore.SetFlash(w, "You are already logged in.", FlashLevelSuccess)
		http.Redirect(w, r, l.SuccessRedirectURL, http.StatusSeeOther)
		return
	}

	if l.loginTemplateCache == nil {
		var err error
		l.loginTemplateCache, err = template.ParseFS(l.TemplateFS, "base.html", "login.html")
		if err != nil {
			panic("unable to parse login template: " + err.Error())
		}
	}
	err := ExecuteTemplate(l.loginTemplateCache, w, "base.html", LoginTemplateData{
		Flash:       flash,
		CallbackURL: callbackURL,
	})
	if err != nil {
		panic("unable to execute login template: " + err.Error())
	}
}

var ErrNoLocalAccount = errors.New("no local account found.")

type LocalAccountGetter interface {
	GetLocalAccount(ctx context.Context, email string) (*LocalAccount, *User, error)
}

type DoLoginHandler struct {
	Log                *slog.Logger
	TemplateFS         fs.FS
	SessionStore       *CookieStore
	LocalAccountGetter LocalAccountGetter
	LoginSessionMaxAge time.Duration
	SuccessRedirectURL string

	loginTemplateCache *template.Template
}

func (d *DoLoginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	loginValues := LoginValues{
		Email:    r.FormValue("email"),
		Password: r.FormValue("password"),
	}
	loginErrors, ok := d.ValidateLoginValues(loginValues)
	if !ok {
		d.Log.Debug("Login validation failed.", "field_errors", loginErrors, "field_values", loginValues)
		d.ExecuteTemplate(w, r, LoginTemplateData{
			Values: loginValues,
			Errors: loginErrors,
		})
		return
	}

	localAccount, user, err := d.LocalAccountGetter.GetLocalAccount(r.Context(), loginValues.Email)
	if err != nil {
		if errors.Is(err, ErrNoLocalAccount) {
			d.Log.Debug("No local account is associated with the email provided.", "email", loginValues.Email)
			d.ExecuteTemplate(w, r, LoginTemplateData{
				Flash: &Flash{
					Message: "Incorrect email or password.",
					Level:   FlashLevelError,
				},
				Values: loginValues,
			})
			return
		}

		d.Log.Error("Unable to get local account.", "reason", err.Error())
		d.ExecuteTemplate(w, r, LoginTemplateData{
			Flash: &Flash{
				Message: "Something went wrong. Please try again later.",
				Level:   FlashLevelError,
			},
			Values: loginValues,
		})
		return
	}

	err = bcrypt.CompareHashAndPassword(localAccount.PasswordHash, []byte(loginValues.Password))
	if err != nil {
		d.Log.Debug("Failed to login. Incorrect password", "email", loginValues.Email)
		d.ExecuteTemplate(w, r, LoginTemplateData{
			Flash: &Flash{
				Message: "Incorrect email or password.",
				Level:   FlashLevelError,
			},
			Values: loginValues,
		})
		return
	}

	loginSession := &LoginSession{
		UserID:      user.ID,
		Avatar:      user.AvatarURL,
		DisplayName: user.DisplayName,
	}
	err = d.SessionStore.Encode(w, SessionKeyLoginSession, loginSession, d.LoginSessionMaxAge)
	if err != nil {
		d.Log.Error("Unable to save login session.", "reason", err.Error())
		d.ExecuteTemplate(w, r, LoginTemplateData{
			Flash: &Flash{
				Message: "Something went wrong. Please try again later.",
				Level:   FlashLevelError,
			},
			Values: loginValues,
		})
		return
	}

	callbackURL := r.FormValue("callback")
	d.Log.Debug("Successfully logged in.", "user_id", user.ID)
	d.SessionStore.SetFlash(w, "Successfully logged in.", FlashLevelSuccess)
	if callbackURL != "" {
		http.Redirect(w, r, callbackURL, http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, d.SuccessRedirectURL, http.StatusSeeOther)
}

func (d *DoLoginHandler) ValidateLoginValues(loginValues LoginValues) (loginErrors LoginErrors, ok bool) {
	ok = true

	if loginValues.Email == "" {
		loginErrors.Email = "Please fill out this field."
		ok = false
	} else if _, err := mail.ParseAddress(loginValues.Email); err != nil {
		loginErrors.Email = "Value is not a valid email."
		ok = false
	}

	if loginValues.Password == "" {
		loginErrors.Password = "Please fill out this field."
		ok = true
	}

	return loginErrors, ok
}

func (d *DoLoginHandler) ExecuteTemplate(w http.ResponseWriter, r *http.Request, data LoginTemplateData) {
	if d.loginTemplateCache == nil {
		var err error
		d.loginTemplateCache, err = template.ParseFS(d.TemplateFS, "base.html", "login.html")
		if err != nil {
			panic("unable to parse login template: " + err.Error())
		}
	}
	err := ExecuteTemplate(d.loginTemplateCache, w, "base.html", data)
	if err != nil {
		panic("unable to execute login template: " + err.Error())
	}
}

func GetLoginSession(ss *CookieStore, w http.ResponseWriter, r *http.Request) (*LoginSession, error) {
	data := &LoginSession{}
	err := ss.Decode(w, r, SessionKeyLoginSession, &data)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func RemoveLoginSession(ss *CookieStore, w http.ResponseWriter, r *http.Request) (*LoginSession, error) {
	data, err := GetLoginSession(ss, w, r)
	ss.Remove(w, SessionKeyLoginSession)

	return data, err
}
