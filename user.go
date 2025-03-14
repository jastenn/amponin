package main

import (
	"bytes"
	"cmp"
	"context"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/alexedwards/scs/v2"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrNoUser     = errors.New("no user found")
	ErrEmailInUse = errors.New("email is already in use")
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

func (l *LocalAccount) ComparePassword(password string) error {
	return bcrypt.CompareHashAndPassword(l.PasswordHash, []byte(password))
}

type SignupPageData struct {
	SessionUser *SessionUser
	Flash       *Flash
	Form        SignupForm
}

type SignupForm struct {
	DisplayName     string
	Email           string
	Password        string
	ConfirmPassword string
	Errors          SignupFormErrors
}

type SignupFormErrors struct {
	DisplayName     string
	Email           string
	Password        string
	ConfirmPassword string
}

func ValidateSignupForm(form SignupForm) (valid bool, errors SignupFormErrors) {
	if form.DisplayName == "" {
		errors.DisplayName = "Please fill out this field."
	} else if len(form.DisplayName) < 1 {
		errors.DisplayName = "Value is too short."
	} else if len(form.DisplayName) > 16 {
		errors.DisplayName = "Value is too long. It must not exceed 16 characters long."
	}

	if form.Email == "" {
		errors.Email = "Please fill out this field."
	} else if IsInvalidEmail(form.Email) {
		errors.Email = "Value is invalid email."
	}

	if form.Password == "" {
		errors.Password = "Please fill out this field."
	} else if len(form.Password) < 8 {
		errors.Password = "Value is too short. It must be at least 8 characters long."
	} else if len(form.Password) > 32 {
		errors.Password = "Value is too long. It must not exceed 32 characters long."
	}

	if form.ConfirmPassword == "" {
		errors.ConfirmPassword = "Please fill out this field."
	} else if form.ConfirmPassword != form.Password {
		errors.ConfirmPassword = "Value doesn't match the password."
	}

	if errors.DisplayName != "" || errors.Email != "" || errors.Password != "" || errors.ConfirmPassword != "" {
		return false, errors
	}

	return true, SignupFormErrors{}
}

//go:embed templates/signup.html templates/base.html
var signupTemplateFS embed.FS
var signupTemplate = template.Must(template.ParseFS(signupTemplateFS, "templates/signup.html", "templates/base.html"))

func RenderSignupPage(w http.ResponseWriter, status int, data SignupPageData) {
	var b bytes.Buffer
	err := signupTemplate.ExecuteTemplate(&b, "base.html", data)
	if err != nil {
		panic("unable to execute signup template: " + err.Error())
	}

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(status)
	w.Write(b.Bytes())
}

type SignupHandler struct {
	Log                *slog.Logger
	SessionManager     *scs.SessionManager
	SuccessRedirectURL string
}

func (s *SignupHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	userSession := GetSessionUser(r.Context())

	if userSession != nil {
		s.Log.Debug("User is currently logged in.", "user_id", userSession.UserID)
		flash := NewFlash("Please log out first before signing up.", FlashLevelError)
		s.SessionManager.Put(r.Context(), SessionKeyFlash, flash)
		http.Redirect(w, r, s.SuccessRedirectURL, http.StatusSeeOther)
		return
	}

	flash, _ := PopSessionFlash(s.SessionManager, r.Context())
	RenderSignupPage(w, http.StatusOK, SignupPageData{
		Flash: flash,
	})

}

type DoSignupHandler struct {
	Log                     *slog.Logger
	SessionManager          *scs.SessionManager
	MailSender              MailSender
	VerificationRedirectURL string
	LoggedInRedirectURL     string
}

type MailSender interface {
	SendMail(ctx context.Context, email string, msg []byte) error
}

const (
	SessionKeySignupValues = "signup_values"
)

type SessionSignupValues struct {
	DisplayName      string
	Email            string
	Password         string
	VerificationCode string
}

func (d *DoSignupHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	loginSession := GetSessionUser(r.Context())
	if loginSession != nil {
		d.Log.Debug("User is currently logged in.", "user_id", loginSession.UserID)
		flash := NewFlash("Please log out first before signing up.", FlashLevelError)
		d.SessionManager.Put(r.Context(), SessionKeyFlash, flash)
		http.Redirect(w, r, d.LoggedInRedirectURL, http.StatusSeeOther)
		return
	}

	form := SignupForm{
		DisplayName:     r.FormValue("display-name"),
		Email:           r.FormValue("email"),
		Password:        r.FormValue("password"),
		ConfirmPassword: r.FormValue("confirm-password"),
	}

	if valid, errors := ValidateSignupForm(form); !valid {
		form.Errors = errors
		d.Log.Debug("Form validation failed.", "field_errors", errors)

		w.WriteHeader(http.StatusUnprocessableEntity)
		RenderSignupPage(w, http.StatusOK, SignupPageData{
			Form: form,
		})
		return
	}

	sessionSignupData := &SessionSignupValues{
		DisplayName:      form.DisplayName,
		Email:            form.Email,
		Password:         form.Password,
		VerificationCode: GenerateVerificationCode(),
	}
	d.SessionManager.Put(r.Context(), SessionKeySignupValues, sessionSignupData)

	go func() {
		var msg bytes.Buffer
		fmt.Fprintln(&msg, "Subject: Amponin Signup Verification")
		fmt.Fprintln(&msg, "")
		fmt.Fprintln(&msg, "Your verification code is:", sessionSignupData.VerificationCode)

		err := d.MailSender.SendMail(context.Background(), sessionSignupData.Email, msg.Bytes())
		if err != nil {
			d.Log.Error("Unable to send verification code to email.", "reason", err.Error())
		} else {
			d.Log.Debug("Verification code was sent successfully.", "email", sessionSignupData.Email)
		}
	}()

	d.Log.Debug("User was redirected into verification redirect url.")
	http.Redirect(w, r, d.VerificationRedirectURL, http.StatusSeeOther)
}

type SignupVerificationPageData struct {
	BasePage
	Flash                 *Flash
	Email                 string
	VerificationCode      string
	VerificationCodeError string
}

//go:embed templates/signup_verification.html templates/base.html
var signupVerificationTemplateFS embed.FS
var signupVerificationTemplate = template.Must(template.ParseFS(signupVerificationTemplateFS, "templates/signup_verification.html", "templates/base.html"))

func RenderSignupVerificationPage(w http.ResponseWriter, status int, data SignupVerificationPageData) {
	var b bytes.Buffer
	err := signupVerificationTemplate.ExecuteTemplate(&b, "base.html", data)
	if err != nil {
		panic("unable to execute signup verification template: " + err.Error())
	}

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(status)
	w.Write(b.Bytes())
}

type SignupVerificationHandler struct {
	Log               *slog.Logger
	SessionManager    *scs.SessionManager
	SignupRedirectURL string
}

func (d *SignupVerificationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sessionSignupData, ok := d.SessionManager.Get(r.Context(), SessionKeySignupValues).(*SessionSignupValues)
	if !ok {
		d.Log.Debug("User haven't started the signup process. No signup values was found.")
		d.SessionManager.Put(r.Context(), SessionKeyFlash, NewErrorFlash("Please signup first."))
		http.Redirect(w, r, d.SignupRedirectURL, http.StatusSeeOther)
		return
	}

	RenderSignupVerificationPage(w, http.StatusOK, SignupVerificationPageData{
		Email: sessionSignupData.Email,
	})
}

type DoSignupVerificatinoHandler struct {
	Log                 *slog.Logger
	SessionManager      *scs.SessionManager
	LocalAccountCreator interface {
		CreateLocalAccount(ctx context.Context, data NewLocalAccount) (*LocalAccount, *User, error)
	}
	SignupRedirectURL   string
	SucccessRedirectURL string
}

type NewLocalAccount struct {
	DisplayName  string
	Email        string
	PasswordHash []byte
	AvatarURL    *string
}

func (d *DoSignupVerificatinoHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	verificationCode := r.FormValue("code")
	sessionSignupData, ok := d.SessionManager.Get(r.Context(), SessionKeySignupValues).(*SessionSignupValues)
	if !ok {
		d.Log.Debug("User haven't started the signup process. No signup values was found.")
		flash := NewErrorFlash("Please signup first.")
		d.SessionManager.Put(r.Context(), SessionKeyFlash, flash)
		http.Redirect(w, r, d.SignupRedirectURL, http.StatusSeeOther)
		return
	}

	if verificationCode != sessionSignupData.VerificationCode {
		d.Log.Debug("Signup email verification code mismatch.", "email", sessionSignupData.Email, "code", verificationCode)
		RenderSignupVerificationPage(w, http.StatusOK, SignupVerificationPageData{
			Email:                 sessionSignupData.Email,
			VerificationCode:      verificationCode,
			VerificationCodeError: "Verification code is invalid.",
		})
		return
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(sessionSignupData.Password), bcrypt.DefaultCost)
	if err != nil {
		d.Log.Error("Failed to generate hash from password.", "reason", err.Error())
		flash := NewErrorFlash("Something went wrong. Please try again later.")
		d.SessionManager.Put(r.Context(), SessionKeyFlash, flash)
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
			flash := NewErrorFlash("Email is already in use.")
			d.SessionManager.Put(r.Context(), SessionKeyFlash, flash)
			http.Redirect(w, r, d.SignupRedirectURL, http.StatusSeeOther)
			return
		}

		d.Log.Error("Failed to create a user local account", "reason", err.Error())
		flash := NewErrorFlash("Something went wrong. Please try again later.")
		d.SessionManager.Put(r.Context(), SessionKeyFlash, flash)
		http.Redirect(w, r, d.SignupRedirectURL, http.StatusSeeOther)
		return
	}

	d.SessionManager.Remove(r.Context(), SessionKeySignupValues)
	d.Log.Debug("New local account was registered.", "id", user.ID)
	flash := NewFlash("Signup successful.", FlashLevelSuccess)
	d.SessionManager.Put(r.Context(), SessionKeyFlash, flash)
	http.Redirect(w, r, d.SucccessRedirectURL, http.StatusSeeOther)
}

type LoginPageData struct {
	SessionUser *SessionUser
	Flash       *Flash
	CallbackURL string
	Form        LoginForm
}

type LoginForm struct {
	Email    string
	Password string
	Errors   LoginFormErrors
}

type LoginFormErrors struct {
	Email    string
	Password string
}

//go:embed templates/login.html templates/base.html
var loginTemplateFS embed.FS
var loginTemplate = template.Must(template.ParseFS(loginTemplateFS, "templates/login.html", "templates/base.html"))

func RenderLoginPage(w http.ResponseWriter, status int, data LoginPageData) {
	var b bytes.Buffer
	err := loginTemplate.ExecuteTemplate(&b, "base.html", data)
	if err != nil {
		panic("unable to execute login template: " + err.Error())
	}

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(status)
	w.Write(b.Bytes())
}

type LoginHandler struct {
	Log                *slog.Logger
	SessionManager     *scs.SessionManager
	SuccessRedirectURL string
}

func (l *LoginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	loginSession := GetSessionUser(r.Context())
	if loginSession != nil {
		l.Log.Debug("User is already logged in.", "user_id", loginSession.UserID)
		flash := NewFlash("You are already logged in.", FlashLevelError)
		l.SessionManager.Put(r.Context(), SessionKeyFlash, flash)
		http.Redirect(w, r, l.SuccessRedirectURL, http.StatusSeeOther)
		return
	}

	flash, _ := PopSessionFlash(l.SessionManager, r.Context())
	RenderLoginPage(w, http.StatusOK, LoginPageData{
		Flash:       flash,
		CallbackURL: r.FormValue("callback"),
	})
}

func ValidateLoginForm(form LoginForm) (valid bool, errors LoginFormErrors) {
	if form.Email == "" {
		errors.Email = "Please fill out this field."
	} else if IsInvalidEmail(form.Email) {
		errors.Email = "Value is invalid email."
	}

	if form.Password == "" {
		errors.Password = "Please fill out this field."
	}

	if errors.Email != "" || errors.Password != "" {
		return false, errors
	}

	return true, LoginFormErrors{}
}

type DoLoginHandler struct {
	Log                       *slog.Logger
	SessionManager            *scs.SessionManager
	LocalAccountGetterByEmail LocalAccountGetterByEmail
	LoginSessionMaxAge        time.Duration
	SuccessRedirectURL        string
}

var ErrNoLocalAccount = errors.New("no local account found")

type LocalAccountGetterByEmail interface {
	GetLocalAccountByEmail(ctx context.Context, email string) (*LocalAccount, *User, error)
}

func (d *DoLoginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	callbackURL := r.URL.Query().Get("callback")

	loginForm := LoginForm{
		Email:    r.FormValue("email"),
		Password: r.FormValue("password"),
	}

	if valid, errors := ValidateLoginForm(loginForm); !valid {
		loginForm.Errors = errors
		RenderLoginPage(w, http.StatusUnprocessableEntity, LoginPageData{
			CallbackURL: callbackURL,
			Form:        loginForm,
		})
		return
	}

	localAccount, user, err := d.LocalAccountGetterByEmail.GetLocalAccountByEmail(r.Context(), loginForm.Email)
	if err != nil {
		if errors.Is(err, ErrNoLocalAccount) {
			d.Log.Debug("No local account is associated with the email provided.", "email", loginForm.Email)
			RenderLoginPage(w, http.StatusUnprocessableEntity, LoginPageData{
				CallbackURL: callbackURL,
				Flash:       NewFlash("Incorrect email or password.", FlashLevelError),
				Form:        loginForm,
			})
			return
		}

		d.Log.Error("Unable to get local account.", "reason", err.Error())
		RenderLoginPage(w, http.StatusInternalServerError, LoginPageData{
			CallbackURL: callbackURL,
			Flash:       NewFlash("Something went wrong. Please try again later.", FlashLevelError),
			Form:        loginForm,
		})
		return
	}

	err = bcrypt.CompareHashAndPassword(localAccount.PasswordHash, []byte(loginForm.Password))
	if err != nil {
		d.Log.Debug("Failed to login. Incorrect password", "email", loginForm.Email)
		RenderLoginPage(w, http.StatusUnprocessableEntity, LoginPageData{
			CallbackURL: callbackURL,
			Flash:       NewFlash("Incorrect email or password.", FlashLevelError),
			Form:        loginForm,
		})
		return
	}

	d.Log.Debug("Successfully logged in.", "user_id", user.ID)
	d.SessionManager.Put(r.Context(), SessionKeyUser, &SessionUser{
		UserID:      user.ID,
		AvatarURL:   user.AvatarURL,
		DisplayName: user.DisplayName,
	})

	flash := NewFlash("Successfully logged in.", FlashLevelSuccess)
	d.SessionManager.Put(r.Context(), SessionKeyFlash, flash)

	http.Redirect(w, r, cmp.Or(callbackURL, d.SuccessRedirectURL), http.StatusSeeOther)
}

type DoLogout struct {
	Log             *slog.Logger
	SessionManager  *scs.SessionManager
	SuccessRedirect string
}

func (d *DoLogout) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sessionUser := GetSessionUser(r.Context())
	if sessionUser == nil {
		d.Log.Debug("No user is logged in.")
		return
	}

	d.SessionManager.Remove(r.Context(), SessionKeyUser)

	d.Log.Debug("User successfully logged out.", "user_id", sessionUser.UserID)
	flash := NewFlash("Successfully logged out.", FlashLevelSuccess)
	d.SessionManager.Put(r.Context(), SessionKeyFlash, flash)

	http.Redirect(w, r, d.SuccessRedirect, http.StatusSeeOther)
}

type AccountPageData struct {
	SessionUser        *SessionUser
	Flash              *Flash
	User               *User
	Focus              string
	GeneralUpdateForm  AccountGeneralUpdateForm
	PasswordUpdateForm AccountPasswordUpdateForm
}

type AccountGeneralUpdateForm struct {
	DisplayName string
	Errors      AccountGeneralUpdateFormError
}

type AccountGeneralUpdateFormError struct {
	Avatar      string
	DisplayName string
}

type AccountPasswordUpdateForm struct {
	CurrentPassword string
	NewPassword     string
	ConfirmPassword string
	Errors          AccountPasswordUpdateFormErrors
}

type AccountPasswordUpdateFormErrors struct {
	CurrentPassword string
	NewPassword     string
	ConfirmPassword string
}

func ValidateAccountPasswordUpdateForm(form AccountPasswordUpdateForm) (valid bool, errors AccountPasswordUpdateFormErrors) {
	if form.CurrentPassword == "" {
		errors.CurrentPassword = "Please fill out this field."
	}

	if form.NewPassword == "" {
		errors.NewPassword = "Please fill out this field."
	} else if len(form.NewPassword) < 8 {
		errors.NewPassword = "Value is too short. It must be at least 8 characters long."
	} else if len(form.NewPassword) > 32 {
		errors.NewPassword = "Value is too long. It must not exceed 32 characters long."
	}

	if form.ConfirmPassword == "" {
		errors.ConfirmPassword = "Please fill out this field."
	} else if form.ConfirmPassword != form.NewPassword {
		errors.ConfirmPassword = "Value doesn't match the password."
	}

	if errors.CurrentPassword != "" || errors.NewPassword != "" || errors.ConfirmPassword != "" {
		return false, errors
	}

	return true, AccountPasswordUpdateFormErrors{}
}

//go:embed templates/account.html templates/base.html
var accountTemplateFS embed.FS
var accountTemplate = template.Must(template.ParseFS(accountTemplateFS, "templates/account.html", "templates/base.html"))

func RenderAccountPage(w http.ResponseWriter, status int, data AccountPageData) {
	var b bytes.Buffer
	err := accountTemplate.ExecuteTemplate(&b, "base.html", data)
	if err != nil {
		panic("unable to execute account template: " + err.Error())
	}

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(status)
	w.Write(b.Bytes())
}

type AccountHandler struct {
	Log            *slog.Logger
	SessionManager *scs.SessionManager
	UserGetterByID UserGetterByID
}

type UserGetterByID interface {
	GetUserByID(ctx context.Context, userID string) (*User, error)
}

func (a *AccountHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sessionUser := GetSessionUser(r.Context())
	if sessionUser == nil {
		RenderClientErrorPageV2(w, http.StatusUnauthorized, "You must be logged in to access this page.")
		return
	}

	user, err := a.UserGetterByID.GetUserByID(r.Context(), sessionUser.UserID)
	if err != nil {
		a.SessionManager.Remove(r.Context(), SessionKeyUser)

		if errors.Is(err, ErrNoUser) {
			RenderClientErrorPageV2(w, http.StatusUnprocessableEntity, "You must be logged in to access this page.")
			return
		}

		a.Log.Error("Unable to get user by its id.", "reason", err.Error())
		RenderClientErrorPageV2(w, http.StatusInternalServerError, "Something went wrong. Please try again later.")
		return
	}

	flash, _ := PopSessionFlash(a.SessionManager, r.Context())
	focus := r.FormValue("focus")
	RenderAccountPage(w, http.StatusOK, AccountPageData{
		SessionUser: sessionUser,
		Flash:       flash,
		User:        user,
		Focus:       focus,
	})
}

type UserInfoUpdater interface {
	UpdateUserInfo(ctx context.Context, userID string, data UserInfoUpdate) (*User, error)
}

type UserInfoUpdate struct {
	Avatar      *string
	DisplayName *string
	Email       *string
}

type EmailUpdateRequest struct {
	Code         string
	UserID       string
	CurrentEmail string
	ExpiresAt    time.Time
	CreatedAt    time.Time
}

var ErrNoEmailUpdateRequest = errors.New("no email update request found")

type NewEmailUpdateRequest struct {
	UserID       string
	CurrentEmail string
	ExpiresAt    time.Time
}

type DoAccountHandler struct {
	Log            *slog.Logger
	SessionManager *scs.SessionManager
	FileStore      FileStore
	UserStore      interface {
		UserGetterByID
		UserInfoUpdater
	}
	LocalAccountStore interface {
		LocalAccountGetterByEmail
		UpdateLocalAccountPassword(ctx context.Context, userID string, passwordHash []byte) (*LocalAccount, error)
	}
	EmailUpdateRequestCreator interface {
		CreateEmailUpdateRequest(context.Context, NewEmailUpdateRequest) (*EmailUpdateRequest, error)
	}
	SuccessRedirectURL       string
	EmailUpdateRequestURL    *url.URL
	EmailUpdateRequestMaxAge time.Duration
	MailSender               MailSender
}

func (d *DoAccountHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	userSession := GetSessionUser(r.Context())
	if userSession == nil {
		BasicHTTPError(w, http.StatusUnauthorized)
		return
	}

	user, err := d.UserStore.GetUserByID(r.Context(), userSession.UserID)
	if err != nil {
		if errors.Is(err, ErrNoUser) {
			d.Log.Debug("User no longer exists.", "user_id", user.ID)
			d.SessionManager.Remove(r.Context(), SessionKeyUser)
			RenderClientErrorPageV2(w, http.StatusUnprocessableEntity, "User no longer exists.")
			return
		}

		d.Log.Error("Unexpected error while parsing avatar.", "error", err.Error())
		RenderClientErrorPageV2(w, http.StatusInternalServerError, "Something went wrong. Please try again later.")
		return
	}

	switch r.FormValue("action") {
	case "general-update":
		d.HandleGeneralUpdate(w, r, userSession, user)
		return
	case "email-update":
		d.HandleEmailUpdate(w, r, userSession, user)
		return
	case "password-update":
		d.HandlePasswordUpdate(w, r, userSession, user)
		return
	default:
		RenderAccountPage(w, http.StatusUnprocessableEntity, AccountPageData{
			SessionUser: userSession,
			User:        user,
			Flash:       NewFlash("Unknown action", FlashLevelError),
		})
		return
	}
}

func (d *DoAccountHandler) HandleGeneralUpdate(w http.ResponseWriter, r *http.Request, sessionUser *SessionUser, user *User) {
	fieldErrors := AccountGeneralUpdateFormError{}

	var avatar *string
	if b, filename, err := FormImage(r, "avatar"); err == nil {
		fileURL, err := d.FileStore.Save("/users/avatar/"+filename, bytes.NewBuffer(b))
		if err != nil {
			d.Log.Error("Unexpected error while saving avatar to file store", "reason", err.Error())
			fieldErrors.Avatar = "Unexpected error while uploading file. Please try again later."
		}
		avatar = &fileURL

	} else if errors.Is(err, ErrUnexpectedFileType) {
		fieldErrors.Avatar = "Only supports image types."

	} else if !errors.Is(err, http.ErrMissingFile) {
		d.Log.Error("Unexpected error while parsing avatar.", "reason", err.Error())
		fieldErrors.Avatar = "Unexpected error while uploading file. Please try again later."
	}

	var displayName *string
	if v := r.FormValue("display-name"); v != "" {
		if l := len(v); l == 1 {
			fieldErrors.DisplayName = "Value is too short."
		} else if l > 16 {
			fieldErrors.DisplayName = "Value is too long. It must not exceed 16 characters long."
		}
		displayName = &v
	}

	if fieldErrors.DisplayName != "" || fieldErrors.Avatar != "" {
		d.Log.Debug("General account info update failed validation.", "field_errors", fieldErrors)
		RenderAccountPage(w, http.StatusUnprocessableEntity, AccountPageData{
			SessionUser: sessionUser,
			User:        user,
			Focus:       "general",
			GeneralUpdateForm: AccountGeneralUpdateForm{
				DisplayName: r.FormValue("display-name"),
				Errors:      fieldErrors,
			},
		})
		return
	}

	user, err := d.UserStore.UpdateUserInfo(r.Context(), sessionUser.UserID, UserInfoUpdate{
		Avatar:      avatar,
		DisplayName: displayName,
	})
	if err != nil {
		d.Log.Error("Unexpected error while updating user info", "reason", err)
		RenderAccountPage(w, http.StatusInternalServerError, AccountPageData{
			SessionUser: sessionUser,
			User:        user,
			Flash:       NewFlash("Unexpected error occurred. Please try again later.", FlashLevelError),
		})
		return
	}

	d.Log.Debug("Account general information was successfully updated.", "user_id", user.ID)

	sessionUser.AvatarURL = user.AvatarURL
	sessionUser.DisplayName = user.DisplayName
	d.SessionManager.Put(r.Context(), SessionKeyUser, sessionUser)

	flash := NewFlash("General Infomation was successfully updated.", FlashLevelSuccess)
	d.SessionManager.Put(r.Context(), SessionKeyFlash, flash)

	http.Redirect(w, r, d.SuccessRedirectURL, http.StatusSeeOther)
}

type EmailUpdateRequestMail struct {
	Recipient string
	Link      string
}

func (d *DoAccountHandler) HandleEmailUpdate(w http.ResponseWriter, r *http.Request, sessionUser *SessionUser, user *User) {
	emailUpdateRequest, err := d.EmailUpdateRequestCreator.CreateEmailUpdateRequest(
		r.Context(),
		NewEmailUpdateRequest{
			UserID:       user.ID,
			CurrentEmail: user.Email,
			ExpiresAt:    time.Now().Add(d.EmailUpdateRequestMaxAge),
		},
	)
	if err != nil {
		d.Log.Error("Unable to create email update request.", "reason", err.Error())
		RenderAccountPage(w, http.StatusInternalServerError, AccountPageData{
			SessionUser: sessionUser,
			Flash:       NewFlash("Something went wrong. Please try again later.", FlashLevelError),
			User:        user,
			Focus:       "email",
		})
		return
	}

	link := &url.URL{}
	*link = *d.EmailUpdateRequestURL
	link.RawQuery = "request-code=" + url.QueryEscape(emailUpdateRequest.Code)

	var msg bytes.Buffer
	RenderEmailUpdateRequestMail(&msg, EmailUpdateRequestMail{
		Recipient: user.DisplayName,
		Link:      link.String(),
	})
	go func() {
		err := d.MailSender.SendMail(r.Context(), user.Email, msg.Bytes())
		if err != nil {
			d.Log.Error("Unable send email.", "reason", err.Error())
		}
	}()

	d.Log.Debug(
		"A link has been sent through your current email.",
		"user_id", emailUpdateRequest.UserID,
		"code", emailUpdateRequest.Code,
	)
	RenderAccountPage(w, http.StatusOK, AccountPageData{
		SessionUser: sessionUser,
		Flash:       NewFlash("A link has been sent through your current email.", FlashLevelSuccess),
		User:        user,
	})
}

//go:embed templates/mail/email_update.html
var emailUpdateRequestMailTemplateRaw string

var emailUpdateRequestMailTemplate = template.Must(template.New("email_update.html").Parse(emailUpdateRequestMailTemplateRaw))

func RenderEmailUpdateRequestMail(w io.Writer, data EmailUpdateRequestMail) {
	var b bytes.Buffer
	err := emailUpdateRequestMailTemplate.Execute(&b, data)
	if err != nil {
		panic("unable to execute mail template: " + err.Error())
	}

	fmt.Fprintln(w, "Subject: Email Update Request")
	fmt.Fprintln(w, "MIME-Version: 1.0")
	fmt.Fprintln(w, "Content-Type: text/html; charset=utf-8")
	fmt.Fprintln(w, "")
	w.Write(b.Bytes())
}

func (d *DoAccountHandler) HandlePasswordUpdate(w http.ResponseWriter, r *http.Request, userSession *SessionUser, user *User) {
	form := AccountPasswordUpdateForm{
		CurrentPassword: r.FormValue("current-password"),
		NewPassword:     r.FormValue("new-password"),
		ConfirmPassword: r.FormValue("confirm-password"),
	}

	if valid, errors := ValidateAccountPasswordUpdateForm(form); !valid {
		form.Errors = errors

		d.Log.Debug("Password update validation failed.", "field_errors", errors)
		RenderAccountPage(w, http.StatusUnprocessableEntity, AccountPageData{
			SessionUser:        userSession,
			User:               user,
			Focus:              "password",
			PasswordUpdateForm: form,
		})
		return
	}

	localAccount, _, err := d.LocalAccountStore.GetLocalAccountByEmail(r.Context(), user.Email)
	if err != nil {
		if errors.Is(err, ErrNoLocalAccount) {
			d.Log.Debug("Failed to update password, no local account was found.")
			RenderAccountPage(w, http.StatusUnprocessableEntity, AccountPageData{
				SessionUser: userSession,
				User:        user,
				Flash:       NewFlash("No local account found.", FlashLevelError),
			})
			return
		}

		d.Log.Error("Uexpected error occurred while getting local account.", "user_id", user.ID)
		RenderAccountPage(w, http.StatusInternalServerError, AccountPageData{
			SessionUser: userSession,
			User:        user,
			Flash:       NewFlash("Something went wrong. Please try again later.", FlashLevelError),
		})
		return
	}

	err = bcrypt.CompareHashAndPassword(localAccount.PasswordHash, []byte(form.CurrentPassword))
	if err != nil {
		form.Errors.CurrentPassword = "Password incorrect."

		d.Log.Debug("Incorrect password", "user_id", user.ID)
		RenderAccountPage(w, http.StatusUnprocessableEntity, AccountPageData{
			SessionUser:        userSession,
			User:               user,
			Focus:              "password",
			PasswordUpdateForm: form,
		})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(form.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		d.Log.Error("Unexpected error occurred while generating password hash.", "reason", err.Error())
		RenderAccountPage(w, http.StatusInternalServerError, AccountPageData{
			SessionUser:        userSession,
			User:               user,
			Flash:              NewFlash("Something went wrong. Please try again later.", FlashLevelError),
			PasswordUpdateForm: form,
		})
		return
	}

	_, err = d.LocalAccountStore.UpdateLocalAccountPassword(r.Context(), user.ID, hash)
	if err != nil {
		d.Log.Error("Unexpected error occurred updating password hash.", "reason", err.Error())
		RenderAccountPage(w, http.StatusInternalServerError, AccountPageData{
			SessionUser:        userSession,
			User:               user,
			Flash:              NewFlash("Something went wrong. Please try again later.", FlashLevelError),
			PasswordUpdateForm: form,
		})
		return
	}

	d.Log.Debug("Local account password update successful.", "user_id", user.ID)
	flash := NewFlash("Password was successfully updated.", FlashLevelSuccess)
	d.SessionManager.Put(r.Context(), SessionKeyFlash, flash)
	http.Redirect(w, r, d.SuccessRedirectURL, http.StatusSeeOther)
}

type AccountEmailUpdatePage struct {
	BasePage
	Flash        *Flash
	LoginSession *SessionUser
	RequestCode  string
	Form         AccountEmailUpdateForm
}

type AccountEmailUpdateForm struct {
	NewEmail string
	Password string
	Errors   AccountEmailUpdateFormErrors
}

type AccountEmailUpdateFormErrors struct {
	NewEmail string
	Password string
}

func ValidateAccountEmailUpdateForm(form AccountEmailUpdateForm) (valid bool, errors AccountEmailUpdateFormErrors) {
	if form.NewEmail == "" {
		errors.NewEmail = "Please fill out this field."
	} else if IsInvalidEmail(form.NewEmail) {
		errors.NewEmail = "Value is invalid email."
	}

	if form.Password == "" {
		errors.Password = "Please fill out this field."
	}

	if errors.NewEmail != "" || errors.Password != "" {
		return false, errors
	}

	return true, AccountEmailUpdateFormErrors{}
}

//go:embed templates/email_update.html templates/base.html
var accountEmailUpdateTemplateFS embed.FS
var accountEmailUpdateTemplate = template.Must(template.ParseFS(accountEmailUpdateTemplateFS, "templates/email_update.html", "templates/base.html"))

func RenderAccountEmailUpdatePage(w http.ResponseWriter, status int, data AccountEmailUpdatePage) {
	var b bytes.Buffer
	err := accountEmailUpdateTemplate.ExecuteTemplate(&b, "base.html", data)
	if err != nil {
		panic("unable to execute email update template: " + err.Error())
	}

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(status)
	w.Write(b.Bytes())
}

type EmailUpdateHandler struct {
	Log                      *slog.Logger
	SessionManager           *scs.SessionManager
	EmailUpdateRequestGetter EmailUpdateRequestGetter
}

type EmailUpdateRequestGetter interface {
	GetEmailUpdateRequest(ctx context.Context, code string) (*EmailUpdateRequest, error)
}

func (a *EmailUpdateHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sessionUser := GetSessionUser(r.Context())

	requestCode := r.URL.Query().Get("request-code")
	if requestCode == "" {
		a.Log.Debug("Request code for email update is invalid.", "request_code", requestCode)
		RenderEmailUpdateErrorPage(w, http.StatusUnprocessableEntity, EmailUpdateErrorPageData{
			SessionUser: sessionUser,
			Message:     "Request code for email update is invalid.",
		})
		return
	}

	emailUpdateRequest, err := a.EmailUpdateRequestGetter.GetEmailUpdateRequest(r.Context(), requestCode)
	if err != nil {
		if errors.Is(err, ErrNoEmailUpdateRequest) {
			a.Log.Debug("Request code for email update is invalid.", "request_code", requestCode)
			RenderEmailUpdateErrorPage(w, http.StatusUnprocessableEntity, EmailUpdateErrorPageData{
				SessionUser: sessionUser,
				Message:     "Request code for email update is invalid.",
			})
			return
		}

		a.Log.Error("Unexpected error occurred while getting email update request by user id.", "reason", err.Error())
		RenderEmailUpdateErrorPage(w, http.StatusInternalServerError, EmailUpdateErrorPageData{
			SessionUser: sessionUser,
			Message:     "Something went wrong. Please try again later.",
		})
		return
	}

	if requestCode != emailUpdateRequest.Code {
		a.Log.Debug("Request code for the user doesn't match the one stored in database.", "request_code", requestCode)
		RenderEmailUpdateErrorPage(w, http.StatusInternalServerError, EmailUpdateErrorPageData{
			SessionUser: sessionUser,
			Message:     "Request code for email update is invalid.",
		})
		return
	}

	if time.Now().After(emailUpdateRequest.ExpiresAt) {
		a.Log.Debug("Request code for email update is no longer valid.", "request_code", requestCode)
		RenderEmailUpdateErrorPage(w, http.StatusBadRequest, EmailUpdateErrorPageData{
			SessionUser: sessionUser,
			Message:     "Request code for email update is no longer valid.",
		})
		return
	}

	RenderAccountEmailUpdatePage(w, http.StatusOK, AccountEmailUpdatePage{
		BasePage: BasePage{
			SessionUser: sessionUser,
		},
		RequestCode: requestCode,
	})
}

type DoEmailUpdateHandler struct {
	Log                     *slog.Logger
	SessionManager          *scs.SessionManager
	EmailUpdateRequestStore interface {
		EmailUpdateRequestGetter
		RemoveEmailUpdateRequest(ctx context.Context, code string) (*EmailUpdateRequest, error)
	}
	LocalAccountGetterByEmail LocalAccountGetterByEmail
	MailSender                MailSender
	VerificationRedirectURL   string
}

const SessionKeyEmailUpdate = "session_email_update_values"

type SessionEmailUpdate struct {
	UserID           string
	NewEmail         string
	VerificationCode string
	Tries            int
}

func (a *DoEmailUpdateHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sessionUser := GetSessionUser(r.Context())

	requestCode := r.FormValue("request-code")
	if requestCode == "" {
		a.Log.Debug("Request code for email update is invalid.", "request_code", requestCode)
		RenderEmailUpdateErrorPage(w, http.StatusUnprocessableEntity, EmailUpdateErrorPageData{
			SessionUser: sessionUser,
			Message:     "Request code for email update is invalid.",
		})
		return
	}

	form := AccountEmailUpdateForm{
		NewEmail: r.FormValue("new-email"),
		Password: r.FormValue("password"),
	}

	if valid, errors := ValidateAccountEmailUpdateForm(form); !valid {
		form.Errors = errors

		a.Log.Debug("Validation failed.", "field_errors", errors)
		RenderAccountEmailUpdatePage(w, http.StatusUnprocessableEntity, AccountEmailUpdatePage{
			BasePage: BasePage{
				SessionUser: sessionUser,
			},
			LoginSession: sessionUser,
			RequestCode:  requestCode,
			Form:         form,
		})
		return
	}

	emailUpdateRequest, err := a.EmailUpdateRequestStore.GetEmailUpdateRequest(r.Context(), requestCode)
	if err != nil {
		if errors.Is(err, ErrNoEmailUpdateRequest) {
			a.Log.Debug("No email update request found.", "request_code", requestCode)
			RenderEmailUpdateErrorPage(w, http.StatusUnprocessableEntity, EmailUpdateErrorPageData{
				SessionUser: sessionUser,
				Message:     "Request code for email update is invalid.",
			})
			return
		}

		a.Log.Error("Unexpected error occurred while getting email update request.", "reason", err.Error())
		RenderEmailUpdateErrorPage(w, http.StatusInternalServerError, EmailUpdateErrorPageData{
			SessionUser: sessionUser,
			Message:     "Something went wrong. Please try again later.",
		})
		return
	}

	if requestCode != emailUpdateRequest.Code {
		a.Log.Debug("Request code for the user doesn't match the one stored in database.", "request_code", requestCode)
		RenderEmailUpdateErrorPage(w, http.StatusUnprocessableEntity, EmailUpdateErrorPageData{
			SessionUser: sessionUser,
			Message:     "Request code for email update is invalid.",
		})
		return
	}

	if time.Now().After(emailUpdateRequest.ExpiresAt) {
		a.Log.Debug("Request code for email update is no longer valid.", "request_code", requestCode)
		RenderEmailUpdateErrorPage(w, http.StatusBadRequest, EmailUpdateErrorPageData{
			SessionUser: sessionUser,
			Message:     "Request code for email update is no longer valid.",
		})
		return
	}

	localAccount, _, err := a.LocalAccountGetterByEmail.GetLocalAccountByEmail(r.Context(), emailUpdateRequest.CurrentEmail)
	if err != nil {
		a.Log.Error("Unable to get user's local account by email.", "user_id", emailUpdateRequest.UserID, "email", emailUpdateRequest.CurrentEmail)
		RenderEmailUpdateErrorPage(w, http.StatusInternalServerError, EmailUpdateErrorPageData{
			SessionUser: sessionUser,
			Message:     "Something went wrong. Please try again later.",
		})
		return
	}

	err = bcrypt.CompareHashAndPassword(localAccount.PasswordHash, []byte(form.Password))
	if err != nil {
		a.Log.Debug("Password comparison failed.", "user_id", emailUpdateRequest.UserID)
		form.Errors.Password = "Incorrect password."
		RenderAccountEmailUpdatePage(w, http.StatusUnprocessableEntity, AccountEmailUpdatePage{
			BasePage: BasePage{
				SessionUser: sessionUser,
			},
			LoginSession: sessionUser,
			RequestCode:  requestCode,
			Form:         form,
		})
		return
	}

	if form.NewEmail == emailUpdateRequest.CurrentEmail {
		a.Log.Debug("The current email is the same as the new email.")
		form.Errors.NewEmail = "Please use a different email."
		RenderAccountEmailUpdatePage(w, http.StatusUnprocessableEntity, AccountEmailUpdatePage{
			BasePage: BasePage{
				SessionUser: sessionUser,
			},
			LoginSession: sessionUser,
			RequestCode:  requestCode,
			Form:         form,
		})
		return
	}

	verificationCode := GenerateVerificationCode()
	go func() {
		var msg bytes.Buffer
		fmt.Fprintln(&msg, "Subject: Amponin Email Update Verification")
		fmt.Fprintln(&msg, "")
		fmt.Fprintln(&msg, "Your verification code is:", verificationCode)

		err := a.MailSender.SendMail(context.Background(), form.NewEmail, msg.Bytes())
		if err != nil {
			a.Log.Error("Failed to send mail.", "email", emailUpdateRequest.CurrentEmail)
		}
	}()

	_, err = a.EmailUpdateRequestStore.RemoveEmailUpdateRequest(r.Context(), requestCode)
	if err != nil {
		a.Log.Error("Unable to remove email update request.", "reason", err.Error())
		RenderEmailUpdateErrorPage(w, http.StatusInternalServerError, EmailUpdateErrorPageData{
			SessionUser: sessionUser,
			Message:     "Something went wrong. Please try again later.",
		})
		return
	}

	a.SessionManager.Put(r.Context(), SessionKeyEmailUpdate, SessionEmailUpdate{
		UserID:           emailUpdateRequest.UserID,
		NewEmail:         form.NewEmail,
		VerificationCode: verificationCode,
	})

	a.Log.Debug("Email verification was sent on email.", "user_id", emailUpdateRequest.UserID)
	http.Redirect(w, r, a.VerificationRedirectURL, http.StatusSeeOther)
}

type EmailUpdateVerificationPageData struct {
	BasePage
	NewEmail              string
	VerificationCode      string
	VerificationCodeError string
}

//go:embed templates/email_update_verification.html templates/base.html
var emailUpdateVerificationTemplateFS embed.FS
var emailUpdateVerificationTemplate = template.Must(template.ParseFS(emailUpdateVerificationTemplateFS, "templates/email_update_verification.html", "templates/base.html"))

func RenderEmailUpdateVerificationPage(w http.ResponseWriter, status int, data EmailUpdateVerificationPageData) {
	var b bytes.Buffer
	err := emailUpdateVerificationTemplate.ExecuteTemplate(&b, "base.html", data)
	if err != nil {
		panic("unable to execute email update verification template: " + err.Error())
	}

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(status)
	w.Write(b.Bytes())
}

type EmailUpdateVerificationHandler struct {
	Log            *slog.Logger
	SessionManager *scs.SessionManager
}

func (e *EmailUpdateVerificationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sessionUser := GetSessionUser(r.Context())

	sessionEmailUpdate, ok := e.SessionManager.Get(r.Context(), SessionKeyEmailUpdate).(*SessionEmailUpdate)
	if !ok {
		e.Log.Debug("State no longer valid for email update verification. Some data from session was missing.")
		flash := NewFlash("Invalid state. Please restart email update process.", FlashLevelError)
		e.SessionManager.Put(r.Context(), SessionKeyFlash, flash)
		RenderEmailUpdateErrorPage(w, http.StatusInternalServerError, EmailUpdateErrorPageData{
			SessionUser: sessionUser,
			Message:     "Invalid state. Please restart email update process.",
		})
		return
	}

	RenderEmailUpdateVerificationPage(w, http.StatusOK, EmailUpdateVerificationPageData{
		BasePage: BasePage{
			SessionUser: sessionUser,
		},
		NewEmail: sessionEmailUpdate.NewEmail,
	})
}

type DoEmailUpdateVerficationHandler struct {
	Log             *slog.Logger
	SessionManager  *scs.SessionManager
	UserInfoUpdater UserInfoUpdater
}

func (d *DoEmailUpdateVerficationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sessionUser := GetSessionUser(r.Context())

	sessionEmailUpdate, ok := d.SessionManager.Get(r.Context(), SessionKeyEmailUpdate).(*SessionEmailUpdate)
	if !ok {
		d.Log.Error("State no longer valid for email update verification. Some data from session was missing.")
		RenderEmailUpdateErrorPage(w, http.StatusInternalServerError, EmailUpdateErrorPageData{
			SessionUser: sessionUser,
			Message:     "Invalid state. Please restart email update process.",
		})
		return
	}

	if sessionEmailUpdate.Tries > 5 {
		d.Log.Error("Too many incorrect verification code attempts.", "user_id", sessionEmailUpdate.UserID)
		d.SessionManager.Remove(r.Context(), SessionKeyEmailUpdate)
		RenderEmailUpdateErrorPage(w, http.StatusInternalServerError, EmailUpdateErrorPageData{
			SessionUser: sessionUser,
			Message:     "Too many incorrect verification code attempts.",
		})
		return
	}

	verificationCode := r.FormValue("verification-code")
	if verificationCode == "" {
		RenderEmailUpdateVerificationPage(w, http.StatusUnprocessableEntity, EmailUpdateVerificationPageData{
			BasePage: BasePage{
				SessionUser: sessionUser,
			},
			NewEmail:              sessionEmailUpdate.NewEmail,
			VerificationCodeError: "Please fill out this field.",
		})
		return
	}

	if verificationCode != sessionEmailUpdate.VerificationCode {
		sessionEmailUpdate.Tries++
		d.SessionManager.Put(r.Context(), SessionKeyEmailUpdate, sessionEmailUpdate)
		RenderEmailUpdateVerificationPage(w, http.StatusOK, EmailUpdateVerificationPageData{
			BasePage: BasePage{
				SessionUser: sessionUser,
			},
			NewEmail:              sessionEmailUpdate.NewEmail,
			VerificationCodeError: "Verification code invalid.",
			VerificationCode:      verificationCode,
		})
		return
	}

	_, err := d.UserInfoUpdater.UpdateUserInfo(r.Context(), sessionEmailUpdate.UserID, UserInfoUpdate{
		Email: &sessionEmailUpdate.NewEmail,
	})
	if err != nil {
		d.Log.Error("Failed to update user email.", "user_id", sessionEmailUpdate.UserID, "new_email", sessionEmailUpdate.NewEmail)
		RenderClientErrorPageV2(w, http.StatusInternalServerError, "Something went wrong. Please try again later.")
		return
	}

	d.SessionManager.Remove(r.Context(), SessionKeyEmailUpdate)
	d.Log.Debug("Email update was successful.", "user_id", sessionEmailUpdate.UserID, "new_email", sessionEmailUpdate.NewEmail)
	RenderEmailUpdateSuccessPage(w, http.StatusOK, EmailUpdateSuccessPageData{
		BasePage: BasePage{
			SessionUser: sessionUser,
		},
		NewEmail: sessionEmailUpdate.NewEmail,
	})
}

type EmailUpdateSuccessPageData struct {
	BasePage
	NewEmail string
}

//go:embed templates/email_update_success.html templates/base.html
var emailUpdateSuccessTemplateFS embed.FS
var emailUpdateSuccessTemplate = template.Must(template.ParseFS(emailUpdateSuccessTemplateFS, "templates/email_update_success.html", "templates/base.html"))

func RenderEmailUpdateSuccessPage(w http.ResponseWriter, status int, data EmailUpdateSuccessPageData) {
	var b bytes.Buffer
	err := emailUpdateSuccessTemplate.ExecuteTemplate(&b, "base.html", data)
	if err != nil {
		panic("unable to execute email update success template: " + err.Error())
	}

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	w.Write(b.Bytes())
}

//go:embed templates/email_update_error.html templates/base.html
var emailUpdateErrorTemplateFS embed.FS
var emailUpdateErrorTemplate = template.Must(template.ParseFS(emailUpdateErrorTemplateFS, "templates/email_update_error.html", "templates/base.html"))

type EmailUpdateErrorPageData struct {
	SessionUser *SessionUser
	Message     string
}

func RenderEmailUpdateErrorPage(w http.ResponseWriter, status int, data EmailUpdateErrorPageData) {
	var b bytes.Buffer
	err := emailUpdateErrorTemplate.ExecuteTemplate(&b, "base.html", data)
	if err != nil {
		panic("unable to execute email update error template: " + err.Error())
	}

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(status)
	w.Write(b.Bytes())
}
