package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/alexedwards/scs/v2"
	nanoid "github.com/matoous/go-nanoid/v2"
	"golang.org/x/crypto/bcrypt"
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

func (l *LocalAccount) ComparePassword(password string) error {
	return bcrypt.CompareHashAndPassword(l.PasswordHash, []byte(password))
}

type SessionUser struct {
	UserID      string
	DisplayName string
	AvatarURL   *string
}

type LoginTemplateData struct {
	LoginSession *SessionUser
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
	SessionManager     *scs.SessionManager
	SuccessRedirectURL string

	loginTemplateCache *template.Template
}

func (l *LoginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	callbackURL := r.FormValue("callback")
	flash, _ := PopSessionFlash(l.SessionManager, r.Context())
	loginSession, _ := GetSessionUser(l.SessionManager, r.Context())
	if loginSession != nil {
		l.Log.Debug("User is already logged in.", "user_id", loginSession.UserID)
		PutSessionFlash(l.SessionManager, r.Context(),
			"You are already logged in.", FlashLevelError)
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

type LocalAccountGetterByEmail interface {
	GetLocalAccountByEmail(ctx context.Context, email string) (*LocalAccount, *User, error)
}

type LocalAccountGetter interface {
	GetLocalAccount(ctx context.Context, userID string) (*LocalAccount, error)
}

type DoLoginHandler struct {
	Log                       *slog.Logger
	TemplateFS                fs.FS
	SessionManager            *scs.SessionManager
	LocalAccountGetterByEmail LocalAccountGetterByEmail
	LoginSessionMaxAge        time.Duration
	SuccessRedirectURL        string

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

	localAccount, user, err := d.LocalAccountGetterByEmail.GetLocalAccountByEmail(r.Context(), loginValues.Email)
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

	PutSessionUser(d.SessionManager, r.Context(), &SessionUser{
		UserID:      user.ID,
		AvatarURL:   user.AvatarURL,
		DisplayName: user.DisplayName,
	})
	callbackURL := r.FormValue("callback")
	d.Log.Debug("Successfully logged in.", "user_id", user.ID)
	PutSessionFlash(d.SessionManager, r.Context(), "Successfully logged in.", FlashLevelSuccess)
	if callbackURL != "" {
		http.Redirect(w, r, callbackURL, http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, d.SuccessRedirectURL, http.StatusSeeOther)
}

const (
	SessionStoreKeyUser  = "session_user"
	SessionKeySignupData = "signup_data"
)

type SessionSignupValues struct {
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
	Log                     *slog.Logger
	TemplateFS              fs.FS
	SessionManager          *scs.SessionManager
	MailSender              MailSender
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

	sessionSignupData := &SessionSignupValues{
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
	sessionSignupData, ok := d.SessionManager.Get(r.Context(), SessionKeySignupData).(*SessionSignupValues)
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
	sessionSignupData, ok := d.SessionManager.Get(r.Context(), SessionKeySignupData).(*SessionSignupValues)
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

type AccountSettingsTemplateData struct {
	Flash                *Flash
	LoginSession         *SessionUser
	User                 *User
	Focus                string
	GeneralUpdateValues  AccountGeneralUpdateValues
	GeneralUpdateErrors  AccountGeneralUpdateErrors
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
	flash, _ := PopSessionFlash(a.SessionManager, r.Context())
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
		Flash:        flash,
		LoginSession: loginSession,
		User:         user,
		Focus:        focus,
	})
}

func (a *AccountSettingsHandler) RenderPage(w http.ResponseWriter, data AccountSettingsTemplateData) {
	if a.accountSettingsTemplateCache == nil {
		var err error
		a.accountSettingsTemplateCache, err = template.ParseFS(a.TemplateFS, "base.html", "account.html")
		if err != nil {
			panic("unable to parse account.html: " + err.Error())
		}
	}
	err := ExecuteTemplate(a.accountSettingsTemplateCache, w, "base.html", data)
	if err != nil {
		panic("unable to execute account.html: " + err.Error())
	}
}

type UserInfoUpdater interface {
	UpdateUserInfo(ctx context.Context, userID string, data UserInfoUpdate) (*User, error)
}

type UserInfoUpdate struct {
	Avatar      *string
	DisplayName *string
	Email       *string
}

type EmailChangeRequest struct {
	Code         string
	UserID       string
	CurrentEmail string
	ExpiresAt    time.Time
	CreatedAt    time.Time
}

var ErrNoEmailChangeRequest = errors.New("no email change request found.")

type NewEmailChangeRequest struct {
	UserID       string
	CurrentEmail string
	ExpiresAt    time.Time
}

type DoAccountHandler struct {
	Log          *slog.Logger
	TemplateFS   fs.FS
	SessionStore *scs.SessionManager
	FileStore    FileStore
	UserStore    interface {
		UserGetterByID
		UserInfoUpdater
	}
	LocalAccountStore interface {
		LocalAccountGetterByEmail
		UpdateLocalAccountPassword(ctx context.Context, userID string, passwordHash []byte) (*LocalAccount, error)
	}
	EmailChangeRequestCreator interface {
		CreateEmailChangeRequest(context.Context, NewEmailChangeRequest) (*EmailChangeRequest, error)
	}
	UnauthenticatedRedirectURL string
	SuccessRedirectURL         string
	EmailChangeRequestURL      *url.URL
	EmailChangeRequestMaxAge   time.Duration
	MailSender                 MailSender

	accountSettingsTemplateCache *template.Template
}

func (d *DoAccountHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	loginSession, _ := GetSessionUser(d.SessionStore, r.Context())
	if loginSession == nil {
		d.Log.Debug("User unauthenticated. The request was redirected to UnauthenticatedRedirectURL.")
		PutSessionFlash(d.SessionStore, r.Context(), "Please log in first.", FlashLevelError)
		return
	}

	user, err := d.UserStore.GetUserByID(r.Context(), loginSession.UserID)
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

	switch r.FormValue("action") {
	case "general-update":
		d.HandleGeneralUpdate(w, r, loginSession, user)
		return
	case "email-update":
		d.HandleEmailUpdate(w, r, loginSession, user)
		return
	case "password-update":
		d.HandlePasswordUpdate(w, r, loginSession, user)
		return
	default:
		d.RenderPage(w, AccountSettingsTemplateData{
			LoginSession: loginSession,
			User:         user,
			Flash: &Flash{
				Level:   FlashLevelError,
				Message: "Unknown action",
			},
		})
		return
	}
}

func (d *DoAccountHandler) HandleGeneralUpdate(w http.ResponseWriter, r *http.Request, loginSession *SessionUser, user *User) {
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

	user, err := d.UserStore.UpdateUserInfo(r.Context(), loginSession.UserID, UserInfoUpdate{
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

	d.Log.Debug("Account general  information was successfully updated.", "user_id", user.ID)
	loginSession.AvatarURL = user.AvatarURL
	loginSession.DisplayName = user.DisplayName
	PutSessionUser(d.SessionStore, r.Context(), loginSession)
	PutSessionFlash(d.SessionStore, r.Context(), "General Infomation was successfully updated.", FlashLevelSuccess)
	http.Redirect(w, r, d.SuccessRedirectURL, http.StatusSeeOther)
}

type EmailChangeRequestMailTemplateData struct {
	Recipient string
	Link      string
}

func (d *DoAccountHandler) HandleEmailUpdate(w http.ResponseWriter, r *http.Request, sessionUser *SessionUser, user *User) {
	emailChangeRequest, err := d.EmailChangeRequestCreator.CreateEmailChangeRequest(
		r.Context(),
		NewEmailChangeRequest{
			UserID:       user.ID,
			CurrentEmail: user.Email,
			ExpiresAt:    time.Now().Add(d.EmailChangeRequestMaxAge),
		},
	)
	if err != nil {
		d.Log.Error("Unable to create email change request.", "reason", err.Error())
		d.RenderPage(w, AccountSettingsTemplateData{
			Flash: &Flash{
				Level:   FlashLevelError,
				Message: "Something went wrong. Please try again later.",
			},
			LoginSession: sessionUser,
			User:         user,
			Focus:        "email",
		})
		return
	}

	link := &url.URL{}
	*link = *d.EmailChangeRequestURL
	link.RawQuery = "request-code=" + url.QueryEscape(emailChangeRequest.Code)

	var msg bytes.Buffer
	msg.WriteString("Subject: Change Email Request\n")
	msg.WriteString("MIME-Version: 1.0\n")
	msg.WriteString("Content-Type: text/html; charset=UTF-8\n")
	msg.WriteString("\n")
	err = template.Must(template.ParseFS(d.TemplateFS, "mail/change_email.html")).
		Execute(&msg, EmailChangeRequestMailTemplateData{
			Recipient: user.DisplayName,
			Link:      link.String(),
		})
	if err != nil {
		d.Log.Error("Unable to execute change email template")
		d.RenderPage(w, AccountSettingsTemplateData{
			Flash: &Flash{
				Level:   FlashLevelError,
				Message: "Something went wrong. Please try again later.",
			},
			LoginSession: sessionUser,
			User:         user,
			Focus:        "email",
		})
		return
	}

	go func() {
		err := d.MailSender.SendMail(r.Context(), user.Email, msg.Bytes())
		if err != nil {
			d.Log.Error("Unable send email.", "reason", err.Error())
		}
	}()

	d.Log.Debug(
		"A link has been sent through your current email.",
		"user_id", emailChangeRequest.UserID,
		"code", emailChangeRequest.Code,
	)
	d.RenderPage(w, AccountSettingsTemplateData{
		Flash: &Flash{
			Level:   FlashLevelSuccess,
			Message: "A link has been sent through your current email.",
		},
		LoginSession: sessionUser,
		User:         user,
	})
}

func (d *DoAccountHandler) HandlePasswordUpdate(w http.ResponseWriter, r *http.Request, userSession *SessionUser, user *User) {
	fieldValues := AccountPasswordUpdateValues{
		CurrentPassword: r.FormValue("current-password"),
		NewPassword:     r.FormValue("new-password"),
		ConfirmPassword: r.FormValue("confirm-password"),
	}

	valid, fieldErrors := d.ValidatePasswordUpdateValues(fieldValues)
	if !valid {
		d.Log.Debug("Password update validation failed.", "field_values", fieldValues, "field_errors", fieldErrors)
		d.RenderPage(w, AccountSettingsTemplateData{
			LoginSession:         userSession,
			User:                 user,
			Focus:                "password",
			PasswordUpdateValues: fieldValues,
			PasswordUpdateErrors: fieldErrors,
		})
		return
	}

	localAccount, _, err := d.LocalAccountStore.GetLocalAccountByEmail(r.Context(), user.Email)
	if err != nil {
		if errors.Is(err, ErrNoLocalAccount) {
			d.Log.Debug("Failed to update password, no local account was found.")
			d.RenderPage(w, AccountSettingsTemplateData{
				LoginSession: userSession,
				User:         user,
				Flash: &Flash{
					Message: "No local account found.",
					Level:   FlashLevelError,
				},
			})
			return
		}

		d.Log.Error("Uexpected error occurred while getting local account.", "user_id", user.ID)
		d.RenderPage(w, AccountSettingsTemplateData{
			LoginSession: userSession,
			User:         user,
			Flash: &Flash{
				Message: "Something went wrong. Please try again later.",
				Level:   FlashLevelError,
			},
		})
		return
	}

	err = bcrypt.CompareHashAndPassword(localAccount.PasswordHash, []byte(fieldValues.CurrentPassword))
	if err != nil {
		d.Log.Error("Incorrect password", "user_id", user.ID)
		d.RenderPage(w, AccountSettingsTemplateData{
			LoginSession:         userSession,
			User:                 user,
			PasswordUpdateValues: fieldValues,
			Focus:                "password",
			PasswordUpdateErrors: AccountPasswordUpdateErrors{
				CurrentPassword: "Incorrect password.",
			},
		})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(fieldValues.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		d.Log.Error("Uexpected error occurred while generating password hash.", "reason", err.Error())
		d.RenderPage(w, AccountSettingsTemplateData{
			LoginSession: userSession,
			User:         user,
			Flash: &Flash{
				Message: "Something went wrong. Please try again later.",
				Level:   FlashLevelError,
			},
		})
		return
	}

	_, err = d.LocalAccountStore.UpdateLocalAccountPassword(r.Context(), user.ID, hash)
	if err != nil {
		d.Log.Error("Uexpected error occurred updating password hash.", "reason", err.Error())
		d.RenderPage(w, AccountSettingsTemplateData{
			LoginSession: userSession,
			User:         user,
			Flash: &Flash{
				Message: "Something went wrong. Please try again later.",
				Level:   FlashLevelError,
			},
		})
		return
	}

	d.Log.Debug("Local account password update successful.", "user_id", user.ID)
	PutSessionFlash(d.SessionStore, r.Context(), "Successfully updated password.", FlashLevelSuccess)
	http.Redirect(w, r, d.SuccessRedirectURL, http.StatusSeeOther)
}

func (d *DoAccountHandler) ValidatePasswordUpdateValues(data AccountPasswordUpdateValues) (valid bool, fieldErrors AccountPasswordUpdateErrors) {
	valid = true

	if data.CurrentPassword == "" {
		fieldErrors.CurrentPassword = "Please fill out this field"
		valid = false
	}

	if l := len(data.NewPassword); l == 0 {
		fieldErrors.NewPassword = "Please fill out this field."
		valid = false
	} else if l < 8 {
		fieldErrors.NewPassword = "Value is too short. It must be at least 8 characters long."
		valid = false
	} else if l > 32 {
		fieldErrors.NewPassword = "Value is too long. It must not exceed 32 characters long."
		valid = false
	}

	if fieldErrors.NewPassword == "" {
		if data.ConfirmPassword == "" {
			fieldErrors.ConfirmPassword = "Password mismatch."
			valid = false
		} else if data.NewPassword != data.ConfirmPassword {
			fieldErrors.ConfirmPassword = "Password mismatch."
			valid = false
		}
	}

	return valid, fieldErrors
}

func (a *DoAccountHandler) RenderPage(w http.ResponseWriter, data AccountSettingsTemplateData) {
	if a.accountSettingsTemplateCache == nil {
		var err error
		a.accountSettingsTemplateCache, err = template.ParseFS(a.TemplateFS, "base.html", "account.html")
		if err != nil {
			panic("unable to parse account settings template: " + err.Error())
		}
	}
	err := ExecuteTemplate(a.accountSettingsTemplateCache, w, "base.html", data)
	if err != nil {
		panic("unable to execute account settings template: " + err.Error())
	}
}

type AccountChangeEmailHandler struct {
	Log                      *slog.Logger
	PageRenderer             PageRenderer
	SessionManager           *scs.SessionManager
	EmailChangeRequestGetter EmailChangeRequestGetter
}

func (a *AccountChangeEmailHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sessionUser, _ := GetSessionUser(a.SessionManager, r.Context())

	requestCode := r.FormValue("request-code")
	if requestCode == "" {
		a.Log.Debug("Request code for email change is invalid.", "request_code", requestCode)
		a.Error(w, sessionUser, "Request code for email change is invalid.")
		return
	}

	emailChangeRequest, err := a.EmailChangeRequestGetter.GetEmailChangeRequest(r.Context(), requestCode)
	if err != nil {
		if errors.Is(err, ErrNoEmailChangeRequest) {
			a.Log.Debug("Request code for email change is invalid.", "request_code", requestCode)
			a.Error(w, sessionUser, "Request code for email change is invalid.")
			return
		}

		a.Log.Error("Unexpected error occurred while getting email change request by user id.", "reason", err.Error())
		a.Error(w, sessionUser, "Something went wrong. Please try again later.")
		return
	}

	if requestCode != emailChangeRequest.Code {
		a.Log.Debug("Request code for the user doesn't match the one stored in database.", "request_code", requestCode)
		a.Error(w, sessionUser, "Request code for email change is invalid.")
		return
	}

	if time.Now().After(emailChangeRequest.ExpiresAt) {
		a.Log.Debug("Request code for email change is no longer valid.", "request_code", requestCode)
		a.Error(w, sessionUser, "Request code for email change is no longer invalid.")
		return
	}

	sessionUser, _ = GetSessionUser(a.SessionManager, r.Context())
	err = a.PageRenderer.RenderPage(w, "change_email.html", AccountChangeEmailPage{
		LoginSession: sessionUser,
		RequestCode:  requestCode,
		Form:         NewAccountChangeEmailForm(),
	})
	if err != nil {
		panic("unable to render change_email.html page: " + err.Error())
	}
}

func (a *AccountChangeEmailHandler) Error(w http.ResponseWriter, sessionUser *SessionUser, message string) {
	err := a.PageRenderer.RenderPage(w, "change_email_error.html", ChangeEmailErrorPage{
		LoginSession: sessionUser,
		Message:      message,
	})
	if err != nil {
		panic(err)
	}
}

type DoAccountChangeEmailHandler struct {
	Log                      *slog.Logger
	PageRenderer             PageRenderer
	SessionManager           *scs.SessionManager
	EmailChangeRequestGetter EmailChangeRequestGetter
	MailSender               MailSender
	VerificationRedirectURL  string
}

type EmailChangeRequestGetter interface {
	GetEmailChangeRequest(ctx context.Context, code string) (*EmailChangeRequest, error)
}

func (a *DoAccountChangeEmailHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sessionUser, _ := GetSessionUser(a.SessionManager, r.Context())
	requestCode := r.FormValue("request-code")
	if requestCode == "" {
		a.Log.Debug("Request code for email change is invalid.", "request_code", requestCode)
		a.Error(w, sessionUser, "Request Code for email change is invalid")
		return
	}

	form := NewAccountChangeEmailForm()
	form.NewEmail = r.FormValue("new-email")
	form.Password = r.FormValue("password")

	form.Check(form.NewEmail == "", "new-email", "Please fill out this field.")
	form.Check(InvalidEmail(form.NewEmail), "new-email", "Value is invalid email.")
	form.Check(form.Password == "", "password", "Please fill out this field.")

	if !form.Valid() {
		a.Log.Debug("Validation failed.", "field_errors", form.FieldErrors)
		a.PageRenderer.RenderPage(w, "change_email.html", AccountChangeEmailPage{
			LoginSession: sessionUser,
			RequestCode:  requestCode,
			Form:         form,
		})
		return
	}

	emailChangeRequest, err := a.EmailChangeRequestGetter.GetEmailChangeRequest(r.Context(), requestCode)
	if err != nil {
		if errors.Is(err, ErrNoEmailChangeRequest) {
			a.Log.Debug("No email change request found.", "request_code", requestCode)
			a.Error(w, sessionUser, "Request Code for email change is invalid")
			return
		}

		a.Log.Error("Unexpected error occurred while getting email change request.", "reason", err.Error())
		a.Error(w, sessionUser, "Something went wrong. Please try again later.")
		return
	}

	if requestCode != emailChangeRequest.Code {
		a.Log.Debug("Request code for the user doesn't match the one stored in database.", "request_code", requestCode)
		a.Error(w, sessionUser, "Request code for email change is invalid.")
		return
	}

	if time.Now().After(emailChangeRequest.ExpiresAt) {
		a.Log.Debug("Request code for email change is no longer valid.", "request_code", requestCode)
		a.Error(w, sessionUser, "Request code for email change is no longer valid.")
		return
	}

	if form.NewEmail == emailChangeRequest.CurrentEmail {
		a.Log.Debug("The current email is the same as the new email.")
		form.Add("new-email", "Please use a different email.")
		a.PageRenderer.RenderPage(w, "change_email.html", AccountChangeEmailPage{
			LoginSession: sessionUser,
			RequestCode:  requestCode,
			Form:         form,
		})
		return
	}

	verificationCode := nanoid.Must(6)
	a.SessionManager.Put(r.Context(), SessionKeyChangeEmail, SessionChangeEmail{
		UserID:           emailChangeRequest.UserID,
		NewEmail:         form.NewEmail,
		VerificationCode: verificationCode,
	})

	go func() {
		err = a.SendMail(r.Context(), form.NewEmail, verificationCode)
		if err != nil {
			a.Log.Error("Failed to send mail.", "email", emailChangeRequest.CurrentEmail)
		}
	}()
	a.Log.Debug("Email verification was sent on email.", "user_id", emailChangeRequest.UserID)
	http.Redirect(w, r, a.VerificationRedirectURL, http.StatusSeeOther)
}

func (d *DoAccountChangeEmailHandler) SendMail(ctx context.Context, email string, code string) error {
	var msg bytes.Buffer
	fmt.Fprintln(&msg, "Subject: Amponin Email Change Verification")
	fmt.Fprintln(&msg, "")
	fmt.Fprintln(&msg, "Your verification code is:", code)

	return d.MailSender.SendMail(context.Background(), email, msg.Bytes())
}

func (d *DoAccountChangeEmailHandler) Error(w http.ResponseWriter, sessionUser *SessionUser, message string) {
	err := d.PageRenderer.RenderPage(w, "change_email_error.html", ChangeEmailErrorPage{
		LoginSession: sessionUser,
		Message:      message,
	})
	if err != nil {
		panic(err)
	}
}

const SessionKeyChangeEmail = "session_email_change_values"

type SessionChangeEmail struct {
	UserID           string
	NewEmail         string
	VerificationCode string
	Tries            int
}

type AccountChangeEmailForm struct {
	NewEmail string
	Password string
	*FieldValidation
}

func NewAccountChangeEmailForm() AccountChangeEmailForm {
	return AccountChangeEmailForm{
		FieldValidation: NewFieldValidation(),
	}
}

type AccountChangeEmailPage struct {
	Flash        *Flash
	LoginSession *SessionUser
	RequestCode  string
	Form         AccountChangeEmailForm
}

type ChangeEmailVerificationHandler struct {
	PageRenderer   PageRenderer
	SessionManager *scs.SessionManager
}

func (c *ChangeEmailVerificationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sessionUser, _ := GetSessionUser(c.SessionManager, r.Context())
	sessionChangeEmail, ok := c.SessionManager.Get(r.Context(), SessionKeyChangeEmail).(*SessionChangeEmail)
	if !ok {
		PutSessionFlash(c.SessionManager, r.Context(), "Invalid state. Please restart email change process.", FlashLevelError)
		c.PageRenderer.RenderPage(w, "email_change_error.html", ChangeEmailErrorPage{
			LoginSession: sessionUser,
			Message:      "Something went wrong. Please restart email change process.",
		})
		return
	}

	err := c.PageRenderer.RenderPage(w, "change_email_verification.html", ChangeEmailVerificationPage{
		LoginSession: sessionUser,
		NewEmail:     sessionChangeEmail.NewEmail,
	})
	if err != nil {
		panic(err)
	}
}

type DoChangeEmailVerficationHandler struct {
	Log             *slog.Logger
	PageRenderer    PageRenderer
	SessionManager  *scs.SessionManager
	UserInfoUpdater UserInfoUpdater
}

func (d *DoChangeEmailVerficationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sessionUser, _ := GetSessionUser(d.SessionManager, r.Context())
	sessionChangeEmail, ok := d.SessionManager.Get(r.Context(), SessionKeyChangeEmail).(*SessionChangeEmail)
	if !ok {
		PutSessionFlash(d.SessionManager, r.Context(), "Invalid state. Please restart email change process.", FlashLevelError)
		err := d.PageRenderer.RenderPage(w, "change_email_error.html", ChangeEmailErrorPage{
			LoginSession: sessionUser,
			Message:      "Invalid state. Please restart email change process.",
		})
		if err != nil {
			panic(err)
		}
		return
	}

	verificationCode := r.FormValue("verification-code")
	if verificationCode == "" {
		err := d.PageRenderer.RenderPage(w, "change_email_verification.html", ChangeEmailVerificationPage{
			LoginSession:          sessionUser,
			NewEmail:              sessionChangeEmail.NewEmail,
			VerificationCodeError: "Please fill out this field.",
		})
		if err != nil {
			panic(err)
		}
		return
	}

	if verificationCode != sessionChangeEmail.VerificationCode {
		sessionChangeEmail.Tries++
		d.SessionManager.Put(r.Context(), SessionKeyChangeEmail, sessionChangeEmail)
		err := d.PageRenderer.RenderPage(w, "change_email_verification.html", ChangeEmailVerificationPage{
			LoginSession:          sessionUser,
			NewEmail:              sessionChangeEmail.NewEmail,
			VerificationCodeError: "Verification code invalid.",
			VerificationCode:      verificationCode,
		})
		if err != nil {
			panic(err)
		}
		return
	}

	_, err := d.UserInfoUpdater.UpdateUserInfo(r.Context(), sessionChangeEmail.UserID, UserInfoUpdate{
		Email: &sessionChangeEmail.NewEmail,
	})
	if err != nil {
		err := d.PageRenderer.RenderPage(w, "change_email_error.html", ChangeEmailErrorPage{
			LoginSession: sessionUser,
			Message:      "Something went wrong. Please try again later.",
		})
		if err != nil {
			panic(err)
		}
	}
	d.Log.Debug("Email change was successful.", "user_id", sessionChangeEmail.UserID, "new_email", sessionChangeEmail.NewEmail)
	err = d.PageRenderer.RenderPage(w, "change_email_success.html", ChangeEmailSuccessPage{
		LoginSession: sessionUser,
		NewEmail:     sessionChangeEmail.NewEmail,
	})
	if err != nil {
		panic(err)
	}
}

type ChangeEmailVerificationPage struct {
	LoginSession          *SessionUser
	NewEmail              string
	VerificationCode      string
	VerificationCodeError string
}

type ChangeEmailSuccessPage struct {
	LoginSession *SessionUser
	NewEmail     string
}

type ChangeEmailErrorPage struct {
	LoginSession *SessionUser
	Message      string
}

type MailSender interface {
	SendMail(ctx context.Context, email string, msg []byte) error
}
