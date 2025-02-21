package main

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/alexedwards/scs/v2"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrNoUser     = errors.New("no user found")
	ErrEmailInUse = errors.New("email is already in use.")
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

type SignupHandler struct {
	Log                  *slog.Logger
	PageTemplateRenderer PageTemplateRenderer
	SessionManager       *scs.SessionManager
	SuccessRedirectURL  string
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
	r, _ = http.NewRequest(r.Method, r.URL.String(), nil)
	err := s.PageTemplateRenderer.RenderPageTemplate(w, "signup.html", SignupPage{
		Flash: flash,
		Form:  NewSignupForm(r),
	})
	if err != nil {
		panic("unable to execute signup template: " + err.Error())
	}
}

type SignupPage struct {
	BasePage
	Flash *Flash
	Form  SignupForm
}

type SignupForm struct {
	DisplayName     string
	Email           string
	Password        string
	ConfirmPassword string

	*FieldValidation
}

func NewSignupForm(r *http.Request) SignupForm {
	return SignupForm{
		DisplayName:     r.FormValue("display-name"),
		Email:           r.FormValue("email"),
		Password:        r.FormValue("password"),
		ConfirmPassword: r.FormValue("confirm-password"),
		FieldValidation: NewFieldValidation(),
	}
}

type DoSignupHandler struct {
	Log                     *slog.Logger
	PageTemplateRenderer    PageTemplateRenderer
	SessionManager          *scs.SessionManager
	MailSender              MailSender
	VerificationRedirectURL string
	LoggedInRedirectURL     string

	signupTemplateCache *template.Template
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

	form := NewSignupForm(r)

	form.Check(form.DisplayName == "", "display-name", "Please fill out this field")
	form.Check(len(form.DisplayName) == 1, "display-name", "Value is too short.")
	form.Check(len(form.DisplayName) > 18, "display-name", "Value is too long. It must not exceed 16 characters long.")
	form.Check(form.Email == "", "email", "Please fill out this field.")
	form.Check(IsInvalidEmail(form.Email), "email", "Value is invalid email.")
	form.Check(form.Password == "", "password", "Please fill out this field.")
	form.Check(len(form.Password) < 8, "password", "Value is too short. It must be at least 8 characters long.")
	form.Check(len(form.Password) > 32, "password", "Value is too long. It must not exceed 32 characters long.")
	form.Check(form.ConfirmPassword == "", "confirm-password", "Please fill out this field.")
	form.Check(form.ConfirmPassword != form.Password, "confirm-password", "Value doesn't match the password")

	if !form.Valid() {
		d.Log.Debug("Form validation failed.", "field_errors", form.FieldErrors)

		w.WriteHeader(http.StatusUnprocessableEntity)
		err := d.PageTemplateRenderer.RenderPageTemplate(w, "signup.html", SignupPage{
			Form: form,
		})
		if err != nil {
			panic(err)
		}
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

const (
	SessionKeySignupValues = "signup_values"
)

type SessionSignupValues struct {
	DisplayName      string
	Email            string
	Password         string
	VerificationCode string
}

type SignupCompletionHandler struct {
	Log                  *slog.Logger
	PageTemplateRenderer PageTemplateRenderer
	SessionManager       *scs.SessionManager
	SignupRedirectURL    string
}

func (d *SignupCompletionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sessionSignupData, ok := d.SessionManager.Get(r.Context(), SessionKeySignupValues).(*SessionSignupValues)
	if !ok {
		d.Log.Debug("User haven't started the signup process. No signup values was found.")
		d.SessionManager.Put(r.Context(), SessionKeyFlash, NewErrorFlash("Please signup first."))
		http.Redirect(w, r, d.SignupRedirectURL, http.StatusSeeOther)
		return
	}

	err := d.PageTemplateRenderer.RenderPageTemplate(w, "signup_verification.html", SignupCompletionPage{
		Email: sessionSignupData.Email,
	})
	if err != nil {
		panic(err)
	}
}

type SignupCompletionPage struct {
	BasePage
	Flash                 *Flash
	Email                 string
	VerificationCode      string
	VerificationCodeError string
}

type DoSignupCompletionHandler struct {
	PageTemplateRenderer PageTemplateRenderer
	Log                  *slog.Logger
	SessionManager       *scs.SessionManager
	LocalAccountCreator  interface {
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

func (d *DoSignupCompletionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
		err := d.PageTemplateRenderer.RenderPageTemplate(w, "signup_verification.html", SignupCompletionPage{
			Email:                 sessionSignupData.Email,
			VerificationCode:      verificationCode,
			VerificationCodeError: "Verification code is invalid.",
		})
		if err != nil {
			panic(err)
		}
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

type LoginHandler struct {
	Log                  *slog.Logger
	PageTemplateRenderer PageTemplateRenderer
	SessionManager       *scs.SessionManager
	SuccessRedirectURL   string
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

	callbackURL := r.FormValue("callback")
	flash, _ := PopSessionFlash(l.SessionManager, r.Context())
	r, _ = http.NewRequest(r.Method, r.URL.String(), nil)
	err := l.PageTemplateRenderer.RenderPageTemplate(w, "login.html", LoginPage{
		Flash:       flash,
		CallbackURL: callbackURL,
		Form:        NewLoginForm(r),
	})
	if err != nil {
		panic("unable to execute login template: " + err.Error())
	}
}

type LoginPage struct {
	BasePage
	Flash       *Flash
	CallbackURL string
	Form        LoginForm
}

type LoginForm struct {
	Email    string
	Password string

	*FieldValidation
}

func NewLoginForm(r *http.Request) LoginForm {
	return LoginForm{
		Email:           r.FormValue("email"),
		Password:        r.FormValue("password"),
		FieldValidation: NewFieldValidation(),
	}
}

type DoLoginHandler struct {
	Log                       *slog.Logger
	PageTemplateRenderer      PageTemplateRenderer
	SessionManager            *scs.SessionManager
	LocalAccountGetterByEmail LocalAccountGetterByEmail
	LoginSessionMaxAge        time.Duration
	SuccessRedirectURL        string
}

var ErrNoLocalAccount = errors.New("no local account found.")

type LocalAccountGetterByEmail interface {
	GetLocalAccountByEmail(ctx context.Context, email string) (*LocalAccount, *User, error)
}

func (d *DoLoginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	callbackURL := r.URL.Query().Get("callback")
	loginForm := NewLoginForm(r)

	loginForm.Check(loginForm.Email == "", "email", "Please fill out this field.")
	loginForm.Check(IsInvalidEmail(loginForm.Email), "email", "Value is invalid email.")
	loginForm.Check(loginForm.Password == "", "password", "Please fill out this field.")

	if !loginForm.Valid() {
		d.Log.Debug("Login validation failed.", "field_errors", loginForm.FieldErrors)
		d.RenderPage(w, LoginPage{Form: loginForm})
		return
	}

	localAccount, user, err := d.LocalAccountGetterByEmail.GetLocalAccountByEmail(r.Context(), loginForm.Email)
	if err != nil {
		if errors.Is(err, ErrNoLocalAccount) {
			d.Log.Debug("No local account is associated with the email provided.", "email", loginForm.Email)
			d.RenderPage(w, LoginPage{
				CallbackURL: callbackURL,
				Flash:       NewFlash("Incorrect email or password.", FlashLevelError),
				Form:        loginForm,
			})
			return
		}

		d.Log.Error("Unable to get local account.", "reason", err.Error())
		d.RenderPage(w, LoginPage{
			CallbackURL: callbackURL,
			Flash:       NewFlash("Something went wrong. Please try again later.", FlashLevelError),
			Form:        loginForm,
		})
		return
	}

	err = bcrypt.CompareHashAndPassword(localAccount.PasswordHash, []byte(loginForm.Password))
	if err != nil {
		d.Log.Debug("Failed to login. Incorrect password", "email", loginForm.Email)
		d.RenderPage(w, LoginPage{
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

func (d *DoLoginHandler) RenderPage(w http.ResponseWriter, data LoginPage) {
	err := d.PageTemplateRenderer.RenderPageTemplate(w, "login.html", data)
	if err != nil {
		panic(err)
	}
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

type AccountSettingsPage struct {
	BasePage
	Flash              *Flash
	User               *User
	Focus              string
	GeneralUpdateForm  AccountGeneralUpdateForm
	PasswordUpdateForm AccountPasswordUpdateForm
}

type AccountGeneralUpdateForm struct {
	DisplayName string

	*FieldValidation
}

func NewAccountGeneralUpdateForm() AccountGeneralUpdateForm {
	return AccountGeneralUpdateForm{
		FieldValidation: NewFieldValidation(),
	}
}

type AccountPasswordUpdateForm struct {
	CurrentPassword string
	NewPassword     string
	ConfirmPassword string

	*FieldValidation
}

func NewAccountPasswordUpdateForm() AccountPasswordUpdateForm {
	return AccountPasswordUpdateForm{
		FieldValidation: NewFieldValidation(),
	}
}

func NewAccountPasswordUpdateFormFromRequest(r *http.Request) AccountPasswordUpdateForm {
	return AccountPasswordUpdateForm{
		CurrentPassword: r.FormValue("current-password"),
		NewPassword:     r.FormValue("new-password"),
		ConfirmPassword: r.FormValue("confirm-password"),
		FieldValidation: NewFieldValidation(),
	}
}

type UserGetterByID interface {
	GetUserByID(ctx context.Context, userID string) (*User, error)
}

type AccountSettingsHandler struct {
	Log                  *slog.Logger
	PageTemplateRenderer PageTemplateRenderer
	SessionManager       *scs.SessionManager
	UserGetterByID       UserGetterByID

	accountSettingsTemplateCache *template.Template
}

func (a *AccountSettingsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sessionUser := GetSessionUser(r.Context())
	if sessionUser == nil {
		BasicHTTPError(w, http.StatusUnauthorized)
	}

	user, err := a.UserGetterByID.GetUserByID(r.Context(), sessionUser.UserID)
	if err != nil {
		if errors.Is(err, ErrNoUser) {
			a.Log.Debug("User no longer exists.", "user_id", sessionUser.UserID)
			a.RenderPage(w, AccountSettingsPage{
				BasePage: BasePage{
					SessionUser: sessionUser,
				},
				Flash: NewFlash("Something went wrong. Please try again later.", FlashLevelError),
			})
			if err != nil {
				panic(err)
			}
			return
		}

		a.Log.Error("Unable to get user by its id.", "reason", err.Error())
		a.RenderPage(w, AccountSettingsPage{
			BasePage: BasePage{
				SessionUser: sessionUser,
			},
			Flash: NewFlash("Something went wrong. Please try again later.", FlashLevelError),
		})
		return
	}

	flash, _ := PopSessionFlash(a.SessionManager, r.Context())
	focus := r.FormValue("focus")
	a.RenderPage(w, AccountSettingsPage{
		BasePage: BasePage{
			SessionUser: sessionUser,
		},
		Flash:              flash,
		User:               user,
		Focus:              focus,
		GeneralUpdateForm:  NewAccountGeneralUpdateForm(),
		PasswordUpdateForm: NewAccountPasswordUpdateForm(),
	})
}

func (a AccountSettingsHandler) RenderPage(w http.ResponseWriter, data AccountSettingsPage) {
	err := a.PageTemplateRenderer.RenderPageTemplate(w, "account.html", data)
	if err != nil {
		panic(err)
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

type EmailUpdateRequest struct {
	Code         string
	UserID       string
	CurrentEmail string
	ExpiresAt    time.Time
	CreatedAt    time.Time
}

var ErrNoEmailUpdateRequest = errors.New("no email update request found.")

type NewEmailUpdateRequest struct {
	UserID       string
	CurrentEmail string
	ExpiresAt    time.Time
}

type DoAccountHandler struct {
	Log                  *slog.Logger
	MailRenderer         MailTemplateRenderer
	PageTemplateRenderer PageTemplateRenderer
	SessionManager       *scs.SessionManager
	FileStore            FileStore
	UserStore            interface {
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

	accountSettingsTemplateCache *template.Template
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
			d.RenderPage(w, AccountSettingsPage{
				BasePage: BasePage{
					SessionUser: userSession,
				},
				Flash: NewFlash("User no longer exists", FlashLevelError),
			})
			return
		}

		d.Log.Error("Unexpected error while parsing avatar.", "error", err.Error())
		d.RenderPage(w, AccountSettingsPage{
			BasePage: BasePage{
				SessionUser: userSession,
			},
			Flash: NewFlash("Unexpected error occurred. Please try again later.", FlashLevelError),
		})
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
		d.RenderPage(w, AccountSettingsPage{
			BasePage: BasePage{
				SessionUser: userSession,
			},
			User:  user,
			Flash: NewFlash("Unknown action", FlashLevelError),
		})
		return
	}
}

func (d *DoAccountHandler) HandleGeneralUpdate(w http.ResponseWriter, r *http.Request, sessionUser *SessionUser, user *User) {
	fieldValidation := NewFieldValidation()

	form := NewAccountGeneralUpdateForm()
	form.DisplayName = strings.TrimSpace(r.FormValue("display-name"))

	var avatar *string
	if b, filename, err := FormImage(r, "avatar"); err == nil {
		fileURL, err := d.FileStore.Save("/users/avatar/"+filename, bytes.NewBuffer(b))
		if err != nil {
			d.Log.Error("Unexpected error while saving avatar to file store", "reason", err.Error())
			fieldValidation.Add("avatar", "Unexpected error while uploading file. Please try again later.")
		}
		avatar = &fileURL

	} else if errors.Is(err, ErrUnexpectedFileType) {
		fieldValidation.Add("avatar", "Only supports image types.")

	} else if !errors.Is(err, http.ErrMissingFile) {
		d.Log.Error("Unexpected error while parsing avatar.", "reason", err.Error())
		fieldValidation.Add("avatar", "Unexpected error while uploading file. Please try again later.")
	}

	var displayName *string
	if form.DisplayName != "" {
		fieldValidation.Check(len(form.DisplayName) == 1, "display-name", "Value is too short.")
		fieldValidation.Check(len(form.DisplayName) > 16, "display-name", "Value is too long. It must not exceed 16 characters long")
		displayName = &form.DisplayName
	}

	if !fieldValidation.Valid() {
		d.Log.Debug("General account info update failed validation.", "field_errors", fieldValidation.FieldErrors)
		d.RenderPage(w, AccountSettingsPage{
			BasePage: BasePage{
				SessionUser: sessionUser,
			},
			User:  user,
			Focus: "general",
			GeneralUpdateForm: AccountGeneralUpdateForm{
				DisplayName:     r.FormValue("display-name"),
				FieldValidation: fieldValidation,
			},
		})
		return
	}

	user, err := d.UserStore.UpdateUserInfo(r.Context(), sessionUser.UserID, UserInfoUpdate{
		Avatar:      avatar,
		DisplayName: displayName,
	})
	if err != nil {
		if errors.Is(err, ErrNoUser) {
			d.Log.Debug("User no longer exists.", "user_id", sessionUser.UserID)
			d.SessionManager.Remove(r.Context(), SessionKeyUser)
			d.RenderPage(w, AccountSettingsPage{
				BasePage: BasePage{
					SessionUser: sessionUser,
				},
				User:  user,
				Flash: NewFlash("User no longer exists.", FlashLevelError),
			})
			return
		}

		d.Log.Error("Unexpected error while updating user info", "reason", err)
		d.RenderPage(w, AccountSettingsPage{
			BasePage: BasePage{
				SessionUser: sessionUser,
			},
			User:  user,
			Flash: NewFlash("Unexpected error occurred. Please try again later.", FlashLevelError),
		})
		return
	}

	d.Log.Debug("Account general  information was successfully updated.", "user_id", user.ID)

	sessionUser.AvatarURL = user.AvatarURL
	sessionUser.DisplayName = user.DisplayName
	d.SessionManager.Put(r.Context(), SessionKeyUser, sessionUser)

	flash := NewFlash("General Infomation was successfully updated.", FlashLevelSuccess)
	d.SessionManager.Put(r.Context(), SessionKeyFlash, flash)

	http.Redirect(w, r, d.SuccessRedirectURL, http.StatusSeeOther)
}

var ErrUnexpectedFileType = errors.New("file from form has an unexpected file type")

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
		d.RenderPage(w, AccountSettingsPage{
			BasePage: BasePage{
				SessionUser: sessionUser,
			},
			Flash: NewFlash("Something went wrong. Please try again later.", FlashLevelError),
			User:  user,
			Focus: "email",
		})
		return
	}

	link := &url.URL{}
	*link = *d.EmailUpdateRequestURL
	link.RawQuery = "request-code=" + url.QueryEscape(emailUpdateRequest.Code)

	var msg bytes.Buffer
	header := map[string]string{
		"Subject": "Update Email Request",
	}

	err = d.MailRenderer.RenderMailTemplate(&msg, "email_update.html", header, EmailUpdateRequestMail{
		Recipient: user.DisplayName,
		Link:      link.String(),
	})
	if err != nil {
		d.Log.Error("Unable to execute update email template", "reason", err.Error())
		d.RenderPage(w, AccountSettingsPage{
			BasePage: BasePage{
				sessionUser,
			},
			Flash: NewFlash("Something went wrong. Please try again later.", FlashLevelError),
			User:  user,
			Focus: "email",
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
		"user_id", emailUpdateRequest.UserID,
		"code", emailUpdateRequest.Code,
	)
	d.RenderPage(w, AccountSettingsPage{
		BasePage: BasePage{
			SessionUser: sessionUser,
		},
		Flash: NewFlash("A link has been sent through your current email.", FlashLevelSuccess),
		User:  user,
	})
}

func (d *DoAccountHandler) HandlePasswordUpdate(w http.ResponseWriter, r *http.Request, userSession *SessionUser, user *User) {
	form := NewAccountPasswordUpdateFormFromRequest(r)

	form.Check(form.CurrentPassword == "", "current-password", "Please fill out this field.")
	form.Check(form.NewPassword == "", "new-password", "Please fill out this field.")
	form.Check(form.ConfirmPassword == "", "confirm-password", "Please fill out this field.")
	form.Check(form.ConfirmPassword != form.NewPassword, "confirm-password", "Value doesn't match the new password")

	if !form.Valid() {
		d.Log.Debug("Password update validation failed.", "field_errors", form.FieldErrors)
		d.RenderPage(w, AccountSettingsPage{
			BasePage: BasePage{
				SessionUser: userSession,
			},
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
			d.RenderPage(w, AccountSettingsPage{
				BasePage: BasePage{
					SessionUser: userSession,
				},
				User:  user,
				Flash: NewFlash("No local account found.", FlashLevelError),
			})
			return
		}

		d.Log.Error("Uexpected error occurred while getting local account.", "user_id", user.ID)
		d.RenderPage(w, AccountSettingsPage{
			BasePage: BasePage{
				SessionUser: userSession,
			},
			User:  user,
			Flash: NewFlash("Something went wrong. Please try again later.", FlashLevelError),
		})
		return
	}

	err = bcrypt.CompareHashAndPassword(localAccount.PasswordHash, []byte(form.CurrentPassword))
	if err != nil {
		form.Add("current-password", "Password incorrect.")
		d.Log.Debug("Incorrect password", "user_id", user.ID)
		d.RenderPage(w, AccountSettingsPage{
			BasePage: BasePage{
				SessionUser: userSession,
			},
			User:               user,
			Focus:              "password",
			PasswordUpdateForm: form,
		})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(form.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		d.Log.Error("Unexpected error occurred while generating password hash.", "reason", err.Error())
		d.RenderPage(w, AccountSettingsPage{
			BasePage: BasePage{
				SessionUser: userSession,
			},
			User:               user,
			Flash:              NewFlash("Something went wrong. Please try again later.", FlashLevelError),
			PasswordUpdateForm: form,
		})
		return
	}

	_, err = d.LocalAccountStore.UpdateLocalAccountPassword(r.Context(), user.ID, hash)
	if err != nil {
		d.Log.Error("Unexpected error occurred updating password hash.", "reason", err.Error())
		d.RenderPage(w, AccountSettingsPage{
			BasePage: BasePage{
				SessionUser: userSession,
			},
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

func (a *DoAccountHandler) RenderPage(w http.ResponseWriter, data AccountSettingsPage) {
	err := a.PageTemplateRenderer.RenderPageTemplate(w, "account.html", data)
	if err != nil {
		panic(err)
	}
}

type AccountEmailUpdateHandler struct {
	Log                      *slog.Logger
	PageTemplateRenderer     PageTemplateRenderer
	SessionManager           *scs.SessionManager
	EmailUpdateRequestGetter EmailUpdateRequestGetter
}

type EmailUpdateRequestGetter interface {
	GetEmailUpdateRequest(ctx context.Context, code string) (*EmailUpdateRequest, error)
}

func (a *AccountEmailUpdateHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sessionUser := GetSessionUser(r.Context())

	requestCode := r.URL.Query().Get("request-code")
	if requestCode == "" {
		a.Log.Debug("Request code for email update is invalid.", "request_code", requestCode)
		a.Error(w, sessionUser, "Request code for email update is invalid.")
		return
	}

	emailUpdateRequest, err := a.EmailUpdateRequestGetter.GetEmailUpdateRequest(r.Context(), requestCode)
	if err != nil {
		if errors.Is(err, ErrNoEmailUpdateRequest) {
			a.Log.Debug("Request code for email update is invalid.", "request_code", requestCode)
			a.Error(w, sessionUser, "Request code for email update is invalid.")
			return
		}

		a.Log.Error("Unexpected error occurred while getting email update request by user id.", "reason", err.Error())
		a.Error(w, sessionUser, "Something went wrong. Please try again later.")
		return
	}

	if requestCode != emailUpdateRequest.Code {
		a.Log.Debug("Request code for the user doesn't match the one stored in database.", "request_code", requestCode)
		a.Error(w, sessionUser, "Request code for email update is invalid.")
		return
	}

	if time.Now().After(emailUpdateRequest.ExpiresAt) {
		a.Log.Debug("Request code for email update is no longer valid.", "request_code", requestCode)
		a.Error(w, sessionUser, "Request code for email update is no longer invalid.")
		return
	}

	err = a.PageTemplateRenderer.RenderPageTemplate(w, "email_update.html", AccountEmailUpdatePage{
		LoginSession: sessionUser,
		RequestCode:  requestCode,
		Form:         NewAccountEmailUpdateForm(),
	})
	if err != nil {
		panic(err)
	}
}

func (a *AccountEmailUpdateHandler) Error(w http.ResponseWriter, sessionUser *SessionUser, message string) {
	err := a.PageTemplateRenderer.RenderPageTemplate(w, "email_update_error.html", EmailUpdateErrorPage{
		BasePage: BasePage{
			SessionUser: sessionUser,
		},
		Message: message,
	})
	if err != nil {
		panic(err)
	}
}

type DoAccountEmailUpdateHandler struct {
	Log                     *slog.Logger
	PageTemplateRenderer    PageTemplateRenderer
	SessionManager          *scs.SessionManager
	EmailUpdateRequestStore interface {
		EmailUpdateRequestGetter
		RemoveEmailUpdateRequest(ctx context.Context, code string) (*EmailUpdateRequest, error)
	}
	LocalAccountGetterByEmail LocalAccountGetterByEmail
	MailSender                MailSender
	VerificationRedirectURL   string
}

func (a *DoAccountEmailUpdateHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sessionUser := GetSessionUser(r.Context())

	requestCode := r.FormValue("request-code")
	if requestCode == "" {
		a.Log.Debug("Request code for email update is invalid.", "request_code", requestCode)
		a.Error(w, sessionUser, "Request Code for email update is invalid")
		return
	}

	form := NewAccountEmailUpdateForm()
	form.NewEmail = r.FormValue("new-email")
	form.Password = r.FormValue("password")

	form.Check(form.NewEmail == "", "new-email", "Please fill out this field.")
	form.Check(IsInvalidEmail(form.NewEmail), "new-email", "Value is invalid email.")
	form.Check(form.Password == "", "password", "Please fill out this field.")

	if !form.Valid() {
		a.Log.Debug("Validation failed.", "field_errors", form.FieldErrors)
		a.RenderPage(w, AccountEmailUpdatePage{
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
			a.Error(w, sessionUser, "Request Code for email update is invalid")
			return
		}

		a.Log.Error("Unexpected error occurred while getting email update request.", "reason", err.Error())
		a.Error(w, sessionUser, "Something went wrong. Please try again later.")
		return
	}

	if requestCode != emailUpdateRequest.Code {
		a.Log.Debug("Request code for the user doesn't match the one stored in database.", "request_code", requestCode)
		a.Error(w, sessionUser, "Request code for email update is invalid.")
		return
	}

	if time.Now().After(emailUpdateRequest.ExpiresAt) {
		a.Log.Debug("Request code for email update is no longer valid.", "request_code", requestCode)
		a.Error(w, sessionUser, "Request code for email update is no longer valid.")
		return
	}

	localAccount, _, err := a.LocalAccountGetterByEmail.GetLocalAccountByEmail(r.Context(), emailUpdateRequest.CurrentEmail)
	if err != nil {
		a.Log.Error("Unable to get user's local account by email.", "user_id", emailUpdateRequest.UserID, "email", emailUpdateRequest.CurrentEmail)
		a.Error(w, sessionUser, "Something went wrong. Please try again later.")
		return
	}

	err = bcrypt.CompareHashAndPassword(localAccount.PasswordHash, []byte(form.Password))
	if err != nil {
		a.Log.Debug("Password comparison failed.", "user_id", emailUpdateRequest.UserID)
		form.Add("password", "Incorrect password.")
		a.RenderPage(w, AccountEmailUpdatePage{
			LoginSession: sessionUser,
			RequestCode:  requestCode,
			Form:         form,
		})
		return
	}

	if form.NewEmail == emailUpdateRequest.CurrentEmail {
		a.Log.Debug("The current email is the same as the new email.")
		form.Add("new-email", "Please use a different email.")
		a.RenderPage(w, AccountEmailUpdatePage{
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
		a.Error(w, sessionUser, "Something went wrong. Please try again later.")
	}

	a.SessionManager.Put(r.Context(), SessionKeyEmailUpdate, SessionEmailUpdate{
		UserID:           emailUpdateRequest.UserID,
		NewEmail:         form.NewEmail,
		VerificationCode: verificationCode,
	})

	a.Log.Debug("Email verification was sent on email.", "user_id", emailUpdateRequest.UserID)
	http.Redirect(w, r, a.VerificationRedirectURL, http.StatusSeeOther)
}

func (d *DoAccountEmailUpdateHandler) RenderPage(w http.ResponseWriter, data AccountEmailUpdatePage) {
	err := d.PageTemplateRenderer.RenderPageTemplate(w, "email_update.html", data)
	if err != nil {
		panic(err)
	}
}

func (d *DoAccountEmailUpdateHandler) Error(w http.ResponseWriter, sessionUser *SessionUser, message string) {
	err := d.PageTemplateRenderer.RenderPageTemplate(w, "email_update_error.html", EmailUpdateErrorPage{
		BasePage: BasePage{
			SessionUser: sessionUser,
		},
		Message: message,
	})
	if err != nil {
		panic(err)
	}
}

const SessionKeyEmailUpdate = "session_email_update_values"

type SessionEmailUpdate struct {
	UserID           string
	NewEmail         string
	VerificationCode string
	Tries            int
}

type AccountEmailUpdateForm struct {
	NewEmail string
	Password string
	*FieldValidation
}

func NewAccountEmailUpdateForm() AccountEmailUpdateForm {
	return AccountEmailUpdateForm{
		FieldValidation: NewFieldValidation(),
	}
}

type AccountEmailUpdatePage struct {
	BasePage
	Flash        *Flash
	LoginSession *SessionUser
	RequestCode  string
	Form         AccountEmailUpdateForm
}

type EmailUpdateVerificationHandler struct {
	Log                  *slog.Logger
	PageTemplateRenderer PageTemplateRenderer
	SessionManager       *scs.SessionManager
}

func (e *EmailUpdateVerificationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sessionUser := GetSessionUser(r.Context())

	sessionEmailUpdate, ok := e.SessionManager.Get(r.Context(), SessionKeyEmailUpdate).(*SessionEmailUpdate)
	if !ok {
		e.Log.Debug("State no longer valid for email update verification. Some data from session was missing.")
		flash := NewFlash("Invalid state. Please restart email update process.", FlashLevelError)
		e.SessionManager.Put(r.Context(), SessionKeyFlash, flash)
		err := e.PageTemplateRenderer.RenderPageTemplate(w, "email_update_error.html", EmailUpdateErrorPage{
			BasePage: BasePage{
				SessionUser: sessionUser,
			},
			Message: "Something went wrong. Please restart email update process.",
		})
		if err != nil {
			panic(err)
		}
		return
	}

	err := e.PageTemplateRenderer.RenderPageTemplate(w, "email_update_verification.html", EmailUpdateVerificationPage{
		BasePage: BasePage{
			SessionUser: sessionUser,
		},
		NewEmail: sessionEmailUpdate.NewEmail,
	})
	if err != nil {
		panic(err)
	}
}

type DoEmailUpdateVerficationHandler struct {
	Log                  *slog.Logger
	PageTemplateRenderer PageTemplateRenderer
	SessionManager       *scs.SessionManager
	UserInfoUpdater      UserInfoUpdater
}

func (d *DoEmailUpdateVerficationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sessionUser := GetSessionUser(r.Context())

	sessionEmailUpdate, ok := d.SessionManager.Get(r.Context(), SessionKeyEmailUpdate).(*SessionEmailUpdate)
	if !ok {
		d.Log.Error("Invalid state. Please restart email update process.")
		err := d.PageTemplateRenderer.RenderPageTemplate(w, "email_update_error.html", EmailUpdateErrorPage{
			BasePage: BasePage{
				SessionUser: sessionUser,
			},
			Message: "Invalid state. Please restart email update process.",
		})
		if err != nil {
			panic(err)
		}
		return
	}

	if sessionEmailUpdate.Tries > 5 {
		d.Log.Error("Too many incorrect verification code attempts.", "user_id", sessionEmailUpdate.UserID)
		d.SessionManager.Remove(r.Context(), SessionKeyEmailUpdate)
		err := d.PageTemplateRenderer.RenderPageTemplate(w, "email_update_error.html", EmailUpdateErrorPage{
			BasePage: BasePage{
				SessionUser: sessionUser,
			},
			Message: "Too many incorrect verification code attempts.",
		})
		if err != nil {
			panic(err)
		}
	}

	verificationCode := r.FormValue("verification-code")
	if verificationCode == "" {
		err := d.PageTemplateRenderer.RenderPageTemplate(w, "email_update_verification.html", EmailUpdateVerificationPage{
			BasePage: BasePage{
				SessionUser: sessionUser,
			},
			NewEmail:              sessionEmailUpdate.NewEmail,
			VerificationCodeError: "Please fill out this field.",
		})
		if err != nil {
			panic(err)
		}
		return
	}

	if verificationCode != sessionEmailUpdate.VerificationCode {
		sessionEmailUpdate.Tries++
		d.SessionManager.Put(r.Context(), SessionKeyEmailUpdate, sessionEmailUpdate)
		err := d.PageTemplateRenderer.RenderPageTemplate(w, "email_update_verification.html", EmailUpdateVerificationPage{
			BasePage: BasePage{
				SessionUser: sessionUser,
			},
			NewEmail:              sessionEmailUpdate.NewEmail,
			VerificationCodeError: "Verification code invalid.",
			VerificationCode:      verificationCode,
		})
		if err != nil {
			panic(err)
		}
		return
	}

	_, err := d.UserInfoUpdater.UpdateUserInfo(r.Context(), sessionEmailUpdate.UserID, UserInfoUpdate{
		Email: &sessionEmailUpdate.NewEmail,
	})
	if err != nil {
		err := d.PageTemplateRenderer.RenderPageTemplate(w, "email_update_error.html", EmailUpdateErrorPage{
			BasePage: BasePage{
				SessionUser: sessionUser,
			},
			Message: "Something went wrong. Please try again later.",
		})
		if err != nil {
			panic(err)
		}
	}

	d.SessionManager.Remove(r.Context(), SessionKeyEmailUpdate)
	d.Log.Debug("Email update was successful.", "user_id", sessionEmailUpdate.UserID, "new_email", sessionEmailUpdate.NewEmail)
	err = d.PageTemplateRenderer.RenderPageTemplate(w, "email_update_success.html", EmailUpdateSuccessPage{
		BasePage: BasePage{
			SessionUser: sessionUser,
		},
		NewEmail: sessionEmailUpdate.NewEmail,
	})
	if err != nil {
		panic(err)
	}
}

type EmailUpdateVerificationPage struct {
	BasePage
	NewEmail              string
	VerificationCode      string
	VerificationCodeError string
}

type EmailUpdateSuccessPage struct {
	BasePage
	NewEmail string
}

type EmailUpdateErrorPage struct {
	BasePage
	Message string
}

type MailSender interface {
	SendMail(ctx context.Context, email string, msg []byte) error
}
