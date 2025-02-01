package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"net/mail"

	"github.com/alexedwards/scs/v2"
	nanoid "github.com/matoous/go-nanoid/v2"
	"golang.org/x/crypto/bcrypt"
)

const (
	SessionStoreKeyUser  = "session_user"
	SessionKeySignupData = "signup_data"
)

type UserSession struct {
	UserID    string
	Email     string
	AvatarURL *string
}

type SessionDataSignupValues struct {
	DisplayName      string
	Email            string
	Password         string
	VerificationCode string
}

type SignupTemplateData struct {
	LoginSession *SessionUser
	Flash        *Flash
	Values       SignupValues
	Errors       SignupErrors
}

type SignupValues struct {
	DisplayName     string
	Email           string
	Password        string
	ConfirmPassword string
}

type SignupErrors struct {
	DisplayName     string
	Email           string
	Password        string
	ConfirmPassword string
}

type SignupHandler struct {
	Log                 *slog.Logger
	TemplateFS          fs.FS
	SessionManager      *scs.SessionManager
	LoggedInRedirectURL string

	signupTemplateCache *template.Template
}

func (s *SignupHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	flash, _ := PopSessionFlash(s.SessionManager, r.Context())
	loginSession, _ := GetSessionUser(s.SessionManager, r.Context())
	if loginSession != nil {
		s.Log.Debug("User is currently logged in.", "user_id", loginSession.UserID)
		PutSessionFlash(
			s.SessionManager, r.Context(),
			"Please log out first before signing up.", FlashLevelError,
		)
		http.Redirect(w, r, s.LoggedInRedirectURL, http.StatusSeeOther)
		return
	}

	if s.signupTemplateCache == nil {
		var err error
		s.signupTemplateCache, err = template.ParseFS(s.TemplateFS, "base.html", "signup.html")
		if err != nil {
			panic("unable to parse signup template: " + err.Error())
		}
	}
	err := ExecuteTemplate(s.signupTemplateCache, w, "base.html", SignupTemplateData{
		Flash: flash,
	})
	if err != nil {
		panic("unable to execute signup template: " + err.Error())
	}
}

type DoSignupHandler struct {
	Log            *slog.Logger
	TemplateFS     fs.FS
	SessionManager *scs.SessionManager
	MailSender     interface {
		SendMail(ctx context.Context, email string, msg []byte) error
	}
	VerificationRedirectURL string

	signupTemplateCache *template.Template
}

func (d *DoSignupHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fieldValues := SignupValues{
		DisplayName:     r.FormValue("display-name"),
		Email:           r.FormValue("email"),
		Password:        r.FormValue("password"),
		ConfirmPassword: r.FormValue("confirm-password"),
	}
	valid, fieldErrors := d.ValidateFieldValues(fieldValues)
	if !valid {
		d.ExecuteTemplate(w, http.StatusBadRequest, SignupTemplateData{
			Values: fieldValues,
			Errors: fieldErrors,
		})
		return
	}

	sessionSignupData := &SessionDataSignupValues{
		DisplayName:      fieldValues.DisplayName,
		Email:            fieldValues.Email,
		Password:         fieldValues.Password,
		VerificationCode: nanoid.MustGenerate("ABCDEFGHIJKLMNPQRSTUVWXYZ123456789", 6),
	}
	d.SessionManager.Put(r.Context(), SessionKeySignupData, sessionSignupData)

	go func() {
		err := d.SendCode(w, fieldValues.Email, sessionSignupData.VerificationCode)
		if err != nil {
			d.Log.Error("Unable to send verification code to email.", "reason", err.Error())
		}
	}()

	http.Redirect(w, r, d.VerificationRedirectURL, http.StatusSeeOther)
}

func (d *DoSignupHandler) ValidateFieldValues(fieldValues SignupValues) (valid bool, fieldErrors SignupErrors) {
	if l := len(fieldValues.DisplayName); l == 0 {
		fieldErrors.DisplayName = "Please fill out this field."
	} else if l == 1 {
		fieldErrors.DisplayName = "Value is too short."
	} else if l > 18 {
		fieldErrors.DisplayName = "Value is too long. It must not exceed 16 characters long."
	}

	if l := len(fieldValues.Email); l == 0 {
		fieldErrors.Email = "Please fill out this field."
	} else if _, err := mail.ParseAddress(fieldValues.Email); err != nil || l > 255 {
		fieldErrors.Email = "Value is not a valid email."
	}

	if l := len(fieldValues.Password); l == 0 {
		fieldErrors.Password = "Please fill out this field."
	} else if l < 8 {
		fieldErrors.Password = "Value is too short. It must be at least 8 characters long."
	} else if l > 32 {
		fieldErrors.Password = "Value is too long. It must not exceed 32 characteres long."
	}

	if fieldValues.ConfirmPassword == "" {
		fieldErrors.ConfirmPassword = "Please fill out this field."
	} else if fieldErrors.Password == "" && fieldValues.ConfirmPassword != fieldValues.Password {
		fieldErrors.ConfirmPassword = "Value doesn't match the password."
	}

	if fieldErrors.DisplayName != "" ||
		fieldErrors.Email != "" ||
		fieldErrors.Password != "" ||
		fieldErrors.ConfirmPassword != "" {

		return false, fieldErrors
	}

	return true, SignupErrors{}
}

func (d *DoSignupHandler) SendCode(w http.ResponseWriter, email, code string) error {
	var b bytes.Buffer
	fmt.Fprintln(&b, "Subject: Amponin Signup Verification")
	fmt.Fprintln(&b, "")
	fmt.Fprintln(&b, "Your verification code is:", code)

	return d.MailSender.SendMail(context.Background(), email, b.Bytes())
}

func (d *DoSignupHandler) ExecuteTemplate(w http.ResponseWriter, status int, data SignupTemplateData) {
	w.WriteHeader(status)
	if d.signupTemplateCache == nil {
		var err error
		d.signupTemplateCache, err = template.ParseFS(d.TemplateFS, "base.html", "signup.html")
		if err != nil {
			panic("unable to parse signup template: " + err.Error())
		}
	}
	err := ExecuteTemplate(d.signupTemplateCache, w, "base.html", data)
	if err != nil {
		panic("unable to execute signup template: " + err.Error())
	}
}

type SignupCompletionTemplateData struct {
	Flash        *Flash
	LoginSession *SessionUser
	Email        string
	Code         string
	CodeError    string
}

type SignupCompletionHandler struct {
	Log               *slog.Logger
	TemplateFS        fs.FS
	SessionManager    *scs.SessionManager
	SignupRedirectURL string

	signupVerificationTemplateCache *template.Template
}

func (d *SignupCompletionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sessionSignupData, ok := d.SessionManager.Get(r.Context(), SessionKeySignupData).(*SessionDataSignupValues)
	if !ok {
		d.Log.Debug("User haven't started the signup process. No signup values was found.")
		PutSessionFlash(
			d.SessionManager, r.Context(),
			"Please signup first.", FlashLevelError,
		)
		http.Redirect(w, r, d.SignupRedirectURL, http.StatusSeeOther)
		return
	}

	if d.signupVerificationTemplateCache == nil {
		var err error
		d.signupVerificationTemplateCache, err = template.ParseFS(d.TemplateFS, "base.html", "signup_completion.html")
		if err != nil {
			panic("unable to parse signup template: " + err.Error())
		}
	}
	data := SignupCompletionTemplateData{
		Email: sessionSignupData.Email,
	}
	err := ExecuteTemplate(d.signupVerificationTemplateCache, w, "base.html", data)
	if err != nil {
		panic("unable to execute signup template: " + err.Error())
	}
}

var ErrEmailInUse = errors.New("email is already in use.")

type NewLocalAccount struct {
	DisplayName  string
	Email        string
	PasswordHash []byte
	AvatarURL    *string
}

type DoSignupCompletionHandler struct {
	TemplateFS          fs.FS
	Log                 *slog.Logger
	SessionManager      *scs.SessionManager
	LocalAccountCreator interface {
		CreateLocalAccount(ctx context.Context, data NewLocalAccount) (*LocalAccount, *User, error)
	}
	SignupRedirectURL   string
	SucccessRedirectURL string

	signupCompletionTemplateCache *template.Template
}

func (d *DoSignupCompletionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	verificationCode := r.FormValue("code")
	sessionSignupData, ok := d.SessionManager.Get(r.Context(), SessionKeySignupData).(*SessionDataSignupValues)
	if !ok {
		d.Log.Debug("User haven't started the signup process. No signup values was found.")
		PutSessionFlash(
			d.SessionManager, r.Context(),
			"Please signup first.", FlashLevelError,
		)
		http.Redirect(w, r, d.SignupRedirectURL, http.StatusSeeOther)
		return
	}

	if verificationCode != sessionSignupData.VerificationCode {
		d.Log.Debug("Signup email verification code mismatch.", "email", sessionSignupData.Email, "code", verificationCode)
		d.ExecuteTemplate(w, http.StatusUnprocessableEntity, SignupCompletionTemplateData{
			Email:     sessionSignupData.Email,
			Code:      verificationCode,
			CodeError: "Verification code is invalid.",
		})
		return
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(sessionSignupData.Password), bcrypt.DefaultCost)
	if err != nil {
		d.Log.Error("Failed to generate hash from password.", "reason", err.Error())

		PutSessionFlash(
			d.SessionManager, r.Context(),
			"Something went wrong. Please try again later.", FlashLevelError,
		)
		http.Redirect(w, r, d.SignupRedirectURL, http.StatusSeeOther)
		return
	}

	_, user, err := d.LocalAccountCreator.CreateLocalAccount(r.Context(), NewLocalAccount{
		DisplayName:  sessionSignupData.DisplayName,
		Email:        sessionSignupData.Email,
		PasswordHash: passwordHash,
	})
	if err != nil {
		if errors.Is(err, ErrEmailInUse) {
			d.Log.Debug("Email is already in use.", "email", sessionSignupData.Email)
			PutSessionFlash(
				d.SessionManager, r.Context(),
				"Email is already in use.", FlashLevelError,
			)
			http.Redirect(w, r, d.SignupRedirectURL, http.StatusSeeOther)
			return
		}

		d.Log.Error("Failed to create a user local account", "reason", err.Error())
		PutSessionFlash(
			d.SessionManager, r.Context(),
			"Something went wrong. Please try again later.", FlashLevelError,
		)
		http.Redirect(w, r, d.SignupRedirectURL, http.StatusSeeOther)
		return
	}

	d.SessionManager.Remove(r.Context(), SessionKeySignupData)
	d.Log.Debug("New local account was registered.", "id", user.ID)
	PutSessionFlash(
		d.SessionManager, r.Context(),
		"Signup successful.", FlashLevelSuccess,
	)
	http.Redirect(w, r, d.SucccessRedirectURL, http.StatusSeeOther)
}

func (d *DoSignupCompletionHandler) ExecuteTemplate(w http.ResponseWriter, status int, data SignupCompletionTemplateData) {
	w.WriteHeader(status)
	if d.signupCompletionTemplateCache == nil {
		var err error
		d.signupCompletionTemplateCache, err = template.ParseFS(d.TemplateFS, "base.html", "signup_completion.html")
		if err != nil {
			panic("unable to parse signup completion template: " + err.Error())
		}
	}
	err := ExecuteTemplate(d.signupCompletionTemplateCache, w, "base.html", data)
	if err != nil {
		panic("unable to execute signup completion template: " + err.Error())
	}
}
