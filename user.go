package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/mail"
	"time"

	nanoid "github.com/matoous/go-nanoid/v2"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
)

var (
	ErrUserEmailInUse = errors.New("user email is already in use.")
	ErrNoUser         = errors.New("user not found.")
)

type User struct {
	ID        string
	Name      string
	Email     string
	AvatarURL *string
	CreatedAt time.Time
	UpdatedAt time.Time
}

var (
	ErrNoAccount = errors.New("no account found.")
)

type LocalAccount struct {
	ID           string
	PasswordHash []byte
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type NewLocalAccount struct {
	Name         string
	Email        string
	PasswordHash []byte
}

type localAccountCreator interface {
	CreateLocalAccount(context.Context, NewLocalAccount) (*LocalAccount, *User, error)
}

type localAccountGetter interface {
	GetLocalAccount(ctx context.Context, email string) (*LocalAccount, *User, error)
}

const ForeignProviderGoogle = "google"

type ForeignAccount struct {
	Provider   string
	ProviderID string
	CreatedAt  time.Time
}

type NewForeignAccount struct {
	Name       string
	Email      string
	AvatarURL  string
	Provider   string
	ProviderID string
}

type foreignAccountCreator interface {
	CreateForeignAccount(context.Context, NewForeignAccount) (*ForeignAccount, *User, error)
}

type foreignAccountGetter interface {
	GetForeignAccount(ctx context.Context, provider string, providerID string) (*ForeignAccount, *User, error)
}

const sessionKeyLoginSession = "session_login"

type loginSession struct {
	UserID    string
	Name      string
	Email     string
	AvatarURL *string
}

type SignupHandler struct {
	Log                     *slog.Logger
	MailSender              MailSender
	SessionStore            *CookieSessionStore
	VerificationRedirectURL string
	GoogleOAuth2Config      *oauth2.Config
}

var signupPage = template.Must(template.ParseFS(embedFS, "templates/pages/signup.html", "templates/pages/base.html"))

type signupPageData struct {
	basePageData
	Flash             *flash
	FieldValues       signupValues
	FieldErrors       signupErrors
	GoogleAuthCodeURL string
}

type signupValues struct {
	Name            string
	Email           string
	Password        string
	ConfirmPassword string
}

type signupErrors struct {
	Name            string
	Email           string
	Password        string
	ConfirmPassword string
}

var verificationEmail = template.Must(template.ParseFS(embedFS, "templates/email/verification.html"))

type verificationEmailData struct {
	Name    string
	Message string
	Code    string
}

func (s *SignupHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	googleAuthState := nanoid.Must(8)
	s.SessionStore.Encode(w, sessionKeyGoogleAuthState, googleAuthState, time.Minute*5)

	googleAuthCodeURL := s.GoogleOAuth2Config.AuthCodeURL(googleAuthState, oauth2.AccessTypeOffline, oauth2.ApprovalForce)
	s.SessionStore.Encode(w, sessionKeyGoogleAuthErrorRedirect, r.URL.RequestURI(), time.Minute*5)

	var loginSession *loginSession
	s.SessionStore.Decode(r, sessionKeyLoginSession, &loginSession)
	if loginSession != nil {
		message := "Please log out first before signing up."
		s.Log.Debug("User is currently logged in. Authenticated users are not allowed to sign up.", "user_id", loginSession.UserID)

		referer := r.Referer()
		if referer == "" {
			flash := newFlash(flashLevelError, message)
			s.SessionStore.Encode(w, sessionKeyFlash, flash, flashMaxAge)
			http.Redirect(w, r, referer, http.StatusSeeOther)
		}

		renderErrorPage(w, errorPageData{
			Status:       http.StatusUnprocessableEntity,
			Message:      message,
			basePageData: basePageData{loginSession},
		})
		return
	}

	if r.Method == http.MethodPost {
		fieldValues := signupValues{
			Name:            r.FormValue("name"),
			Email:           r.FormValue("email"),
			Password:        r.FormValue("password"),
			ConfirmPassword: r.FormValue("confirm-password"),
		}

		fieldErrors, valid := s.validate(fieldValues)
		if !valid {
			err := RenderPage(w, signupPage, http.StatusOK, signupPageData{
				FieldValues:       fieldValues,
				FieldErrors:       fieldErrors,
				GoogleAuthCodeURL: googleAuthCodeURL,
			})
			if err != nil {
				s.Log.Error("Unable to render page.", "error", err.Error())
				renderErrorPage(w, errorPageData{
					Status:  http.StatusInternalServerError,
					Message: clientMessageUnexpectedError,
				})
				return
			}
			return
		}

		verificationCode := nanoid.MustGenerate(nanoidGenerator, 6)

		fmt.Println("signup handler field values:", fieldValues)

		data := signupVerification{
			Values:           fieldValues,
			VerificationCode: verificationCode,
		}
		s.SessionStore.Encode(w, sessionKeySignupVerification, data, time.Minute*5)

		var b bytes.Buffer

		fmt.Fprintln(&b, "Subject: Please Confirm Your Email Address")
		fmt.Fprintln(&b, "Content-Type: text/html")
		fmt.Fprintln(&b, "")

		err := verificationEmail.Execute(&b, verificationEmailData{
			Name:    fieldValues.Name,
			Message: "Thanks for signing up.",
			Code:    verificationCode,
		})
		if err != nil {
			s.Log.Error("Unable to execute confirmation mail template.", "error", err.Error())
			renderErrorPage(w, errorPageData{
				Status:  http.StatusInternalServerError,
				Message: clientMessageUnexpectedError,
			})
			return
		}

		go func() {
			err = s.MailSender.SendMail(r.Context(), fieldValues.Email, b.Bytes())
			if err != nil {
				s.Log.Error("Unable to send confirmation email.", "error", err.Error())
			}
		}()

		flash := newFlash(flashLevelSuccess, "Verification code sent.")
		s.SessionStore.Encode(w, sessionKeyFlash, flash, flashMaxAge)

		http.Redirect(w, r, s.VerificationRedirectURL, http.StatusSeeOther)
		return
	}

	var flash *flash
	s.SessionStore.DecodeAndRemove(w, r, sessionKeyFlash, &flash)

	err := RenderPage(w, signupPage, http.StatusOK, signupPageData{
		Flash:             flash,
		GoogleAuthCodeURL: googleAuthCodeURL,
	})
	if err != nil {
		s.Log.Error("Unable to render page.", "error", err.Error())
		renderErrorPage(w, errorPageData{
			Status:  http.StatusInternalServerError,
			Message: clientMessageUnexpectedError,
		})
		return
	}
}

func (s *SignupHandler) validate(fieldValues signupValues) (fieldErrors signupErrors, valid bool) {
	if l := len(fieldValues.Name); l == 0 {
		fieldErrors.Name = "Please fill out this field."
	} else if l == 1 {
		fieldErrors.Name = "Value is too short."
	} else if l > 18 {
		fieldErrors.Name = "Value is too long. It must not exceed 18 characters long."
	}

	if l := len(fieldValues.Email); l == 0 {
		fieldErrors.Email = "Please fill out this field."
	} else if _, err := mail.ParseAddress(fieldValues.Email); l > 255 || err != nil {
		fieldErrors.Email = "Value is invalid email."
	}

	if l := len(fieldValues.Password); l == 0 {
		fieldErrors.Password = "Please fill out this field."
	} else if l < 8 {
		fieldErrors.Password = "Value is too short. It must be at least 8 characters long."
	} else if l > 32 {
		fieldErrors.Password = "Value is too long. It must not exceed 32 characters long."
	}

	if fieldValues.ConfirmPassword == "" {
		fieldErrors.ConfirmPassword = "Please fill out this field."
	} else if fieldValues.ConfirmPassword != fieldValues.Password {
		fieldErrors.ConfirmPassword = "Value doesn't match the password."
	}

	if fieldErrors.Name != "" ||
		fieldErrors.Email != "" ||
		fieldErrors.Password != "" ||
		fieldErrors.ConfirmPassword != "" {

		return fieldErrors, false
	}

	return signupErrors{}, true
}

type SignupVerificationHandler struct {
	Log                 *slog.Logger
	SessionStore        *CookieSessionStore
	LocalAccountCreator localAccountCreator
	SignupURL           string
	LoginURL            string
}

const sessionKeySignupVerification = "session_signup_verification"

type signupVerification struct {
	Values           signupValues
	VerificationCode string
}

var signupVerificationPage = template.Must(template.ParseFS(embedFS, "templates/pages/signup-verification.html", "templates/pages/base.html"))

type signupVerificationPageData struct {
	basePageData
	Flash                 *flash
	VerificationCode      string
	VerificationCodeError string
}

func (s *SignupVerificationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		verificationCode := r.FormValue("verification-code")

		var signupVerification signupVerification
		err := s.SessionStore.Decode(r, sessionKeySignupVerification, &signupVerification)
		if err != nil {
			s.Log.Error("Unable to decode signup verification from session.", "error", err.Error())
			flash := newFlash(flashLevelError, "Please start the signup process.")
			s.SessionStore.Encode(w, sessionKeyFlash, flash, flashMaxAge)
			http.Redirect(w, r, s.SignupURL, http.StatusSeeOther)
			return
		}

		if signupVerification.VerificationCode != verificationCode {
			s.renderPage(w, http.StatusOK, signupVerificationPageData{
				VerificationCode:      verificationCode,
				VerificationCodeError: "Verification code is invalid.",
			})
			return
		}

		passwordHash, err := bcrypt.GenerateFromPassword([]byte(signupVerification.Values.Password), bcrypt.DefaultCost)
		if err != nil {
			s.Log.Error("Unable to generate hash from password.", "error", err.Error())
			s.renderPage(w, http.StatusOK, signupVerificationPageData{
				Flash:            newFlash(flashLevelError, clientMessageUnexpectedError),
				VerificationCode: verificationCode,
			})
			return
		}

		fmt.Println("data", signupVerification)

		user, localAccount, err := s.LocalAccountCreator.CreateLocalAccount(r.Context(), NewLocalAccount{
			Name:         signupVerification.Values.Name,
			Email:        signupVerification.Values.Email,
			PasswordHash: passwordHash,
		})
		if err != nil {
			if errors.Is(err, ErrUserEmailInUse) {
				s.Log.Info("Email is already in use.", "email", signupVerification.Values.Email)
				flash := newFlash(flashLevelError, "Email is already in use.")
				s.SessionStore.Encode(w, sessionKeyFlash, flash, flashMaxAge)
				http.Redirect(w, r, s.SignupURL, http.StatusSeeOther)
				return
			}

			s.Log.Error("Unable to create local account.", "error", err.Error())

			s.renderPage(w, http.StatusOK, signupVerificationPageData{
				Flash:            newFlash(flashLevelError, clientMessageUnexpectedError),
				VerificationCode: verificationCode,
			})
			return
		}

		s.Log.Info("Successfully created a local account.", "user_id", user.ID, "local_account_id", localAccount.ID)
		flash := newFlash(flashLevelSuccess, "Successfully created an account.")
		s.SessionStore.Encode(w, sessionKeyFlash, flash, flashMaxAge)
		http.Redirect(w, r, s.SignupURL, http.StatusSeeOther)
		return
	}

	var flash *flash
	s.SessionStore.Decode(r, sessionKeyFlash, &flash)
	s.renderPage(w, http.StatusOK, signupVerificationPageData{
		Flash: flash,
	})
}

func (s *SignupVerificationHandler) renderPage(w http.ResponseWriter, status int, data signupVerificationPageData) {
	err := RenderPage(w, signupVerificationPage, status, data)
	if err != nil {
		s.Log.Error("Unable to render page.", "error", err.Error())
		renderErrorPage(w, errorPageData{
			Status:  http.StatusInternalServerError,
			Message: clientMessageUnexpectedError,
		})
		return
	}
}

type LoginHandler struct {
	Log                *slog.Logger
	SessionStore       *CookieSessionStore
	SuccessRedirect    string
	GoogleAuthConfig   *oauth2.Config
	LocalAccountGetter localAccountGetter
	LoginSessionMaxAge time.Duration
}

type loginPageData struct {
	basePageData
	Flash             *flash
	FieldValues       loginValues
	FieldErrors       loginErrors
	GoogleAuthCodeURL string
}

type loginValues struct {
	Email    string
	Password string
}

type loginErrors struct {
	Email    string
	Password string
}

var loginPage = template.Must(template.ParseFS(embedFS, "templates/pages/login.html", "templates/pages/base.html"))

func (l *LoginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var loginSessionData *loginSession
	l.SessionStore.Decode(r, sessionKeyLoginSession, &loginSessionData)

	if loginSessionData != nil {
		l.Log.Debug("User is already logged in.", "user_id", loginSessionData.UserID)
		flash := newFlash(flashLevelSuccess, "You are already logged in.")
		l.SessionStore.Encode(w, sessionKeyFlash, flash, flashMaxAge)
		http.Redirect(w, r, l.SuccessRedirect, http.StatusSeeOther)
		return
	}

	if r.Method == http.MethodPost {
		fieldValues := loginValues{
			Email:    r.FormValue("email"),
			Password: r.FormValue("password"),
		}

		fieldErrors, valid := l.validateFields(fieldValues)
		if !valid {
			l.renderPage(w, r, http.StatusUnprocessableEntity, loginPageData{
				FieldValues: fieldValues,
				FieldErrors: fieldErrors,
			})
			return
		}

		localAccount, user, err := l.LocalAccountGetter.GetLocalAccount(r.Context(), fieldValues.Email)
		if err != nil {
			switch {
			case errors.Is(err, ErrNoUser):
				l.Log.Debug("User doesn't exists", "user_email", fieldValues.Email)
				l.renderPage(w, r, http.StatusUnprocessableEntity, loginPageData{
					Flash:       newFlash(flashLevelError, "Incorrect email or password."),
					FieldValues: fieldValues,
				})
				return
			case errors.Is(err, ErrNoAccount):
				l.Log.Debug("Account doesn't exists.", "user_email", fieldValues.Email)
				l.renderPage(w, r, http.StatusUnprocessableEntity, loginPageData{
					Flash:       newFlash(flashLevelError, "Incorrect email or password."),
					FieldValues: fieldValues,
				})
				return
			default:
				l.Log.Error("Unexpected error while getting local account.", "error", err.Error())
				l.renderPage(w, r, http.StatusInternalServerError, loginPageData{
					Flash:       newFlash(flashLevelError, clientMessageUnexpectedError),
					FieldValues: fieldValues,
				})
				return
			}
		}

		err = bcrypt.CompareHashAndPassword(localAccount.PasswordHash, []byte(fieldValues.Password))
		if err != nil {
			l.Log.Debug("Password comparison failed.", "error", err.Error())
			l.renderPage(w, r, http.StatusUnprocessableEntity, loginPageData{
				Flash:       newFlash(flashLevelError, "Incorrect email or password."),
				FieldValues: fieldValues,
			})
			return
		}

		loginSessionData := loginSession{
			UserID:    user.ID,
			Name:      user.Name,
			Email:     user.Email,
			AvatarURL: user.AvatarURL,
		}
		err = l.SessionStore.Encode(w, sessionKeyLoginSession, loginSessionData, l.LoginSessionMaxAge)
		if err != nil {
			l.Log.Error("Unable to create new login session.", "user_id", loginSessionData.UserID, "error", err.Error())
			l.renderPage(w, r, http.StatusInternalServerError, loginPageData{
				Flash:       newFlash(flashLevelError, clientMessageUnexpectedError),
				FieldValues: fieldValues,
			})
			return
		}

		flash := newFlash(flashLevelSuccess, "Successfully logged in.")
		l.SessionStore.Encode(w, sessionKeyFlash, flash, flashMaxAge)
		http.Redirect(w, r, l.SuccessRedirect, http.StatusSeeOther)
		return
	}

	var flashData *flash
	l.SessionStore.DecodeAndRemove(w, r, sessionKeyFlash, &flashData)

	l.renderPage(w, r, http.StatusOK, loginPageData{
		Flash: flashData,
	})
}

func (l *LoginHandler) validateFields(values loginValues) (errors loginErrors, valid bool) {
	if l := len(values.Email); l == 0 {
		errors.Email = "Please fill out this field."
	} else if _, err := mail.ParseAddress(values.Email); err != nil || l > 255 {
		errors.Email = "Value is invalid email."
	}

	if l := len(values.Password); l == 0 {
		errors.Password = "Please fill out this field."
	}

	if errors.Email != "" || errors.Password != "" {
		return errors, false
	}

	return errors, true
}

func (l *LoginHandler) renderPage(w http.ResponseWriter, r *http.Request, status int, data loginPageData) {
	if data.GoogleAuthCodeURL == "" {
		googleAuthState := nanoid.Must(8)
		l.SessionStore.Encode(w, sessionKeyGoogleAuthState, googleAuthState, time.Minute*5)

		data.GoogleAuthCodeURL = l.GoogleAuthConfig.AuthCodeURL(googleAuthState, oauth2.AccessTypeOffline, oauth2.ApprovalForce)
		l.SessionStore.Encode(w, sessionKeyGoogleAuthErrorRedirect, r.URL.RequestURI(), time.Minute*5)
	}

	err := RenderPage(w, loginPage, status, data)
	if err != nil {
		l.Log.Error("Unable to render page.", "error", err.Error())
		renderErrorPage(w, errorPageData{
			Status:  http.StatusInternalServerError,
			Message: clientMessageUnexpectedError,
		})
		return
	}
}

type GoogleAuthRedirectHandler struct {
	Log                   *slog.Logger
	GoogleAuthConfig      *oauth2.Config
	SessionStore          *CookieSessionStore
	ForeignAccountCreator foreignAccountCreator
	ForeignAccountGetter  foreignAccountGetter
	LoginSessionMaxAge    time.Duration
	SuccessRedirect       string
}

const sessionKeyGoogleAuthState = "google_auth_state"
const sessionKeyGoogleAuthErrorRedirect = "google_auth_error_redirect"

func (g *GoogleAuthRedirectHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var state string
	g.SessionStore.DecodeAndRemove(w, r, sessionKeyGoogleAuthState, &state)
	if state != r.FormValue("state") {
		g.Log.Debug("State mismatch.", "session_state", state, "redirect_state", r.FormValue("state"))
		g.Error(w, r, http.StatusUnprocessableEntity, "Request state is invalid.")
		return
	}

	code := r.FormValue("code")
	tok, err := g.GoogleAuthConfig.Exchange(r.Context(), code)
	if err != nil {
		g.Log.Error("Unable to exchange code.", "error", err.Error())
		g.Error(w, r, http.StatusInternalServerError, clientMessageUnexpectedError)
		return
	}

	res, err := g.GoogleAuthConfig.Client(r.Context(), tok).Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		g.Log.Error("Unable to retrieve user information.", "error", err.Error())
		g.Error(w, r, http.StatusInternalServerError, clientMessageUnexpectedError)
		return
	}

	var result struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Email   string `json:"email"`
		Picture string `json:"picture"`
	}
	err = json.NewDecoder(res.Body).Decode(&result)
	if err != nil {
		g.Log.Error("Unable to decode userinfo query result.", "error", err.Error())
		g.Error(w, r, http.StatusInternalServerError, clientMessageUnexpectedError)
		return
	}

	account, user, err := g.ForeignAccountGetter.GetForeignAccount(r.Context(), result.ID, ForeignProviderGoogle)
	if err != nil && !errors.Is(err, ErrNoAccount) {
		g.Log.Error("Unexpected error while getting foreign account.", "error", err.Error())
		g.Error(w, r, http.StatusInternalServerError, clientMessageUnexpectedError)
		return
	}
	if account == nil || errors.Is(err, ErrNoAccount) {
		account, user, err = g.ForeignAccountCreator.CreateForeignAccount(r.Context(), NewForeignAccount{
			ProviderID: result.ID,
			Provider:   ForeignProviderGoogle,
			AvatarURL:  result.Picture,
			Name:       result.Name,
			Email:      result.Email,
		})
		if err != nil {
			if errors.Is(err, ErrUserEmailInUse) {
				g.Log.Debug("User is registered with different provider.", "email", result.Email)
				g.Error(w, r, http.StatusUnprocessableEntity, "User is registered with different provider.")
				return
			}

			g.Log.Error("Unable to create foreign account.", "error", err.Error())
			g.Error(w, r, http.StatusInternalServerError, clientMessageUnexpectedError)
			return
		}

		g.Log.Debug("New user was created with foreign account.",
			"user_id", user.ID,
			"foreign_account_provider", account.Provider,
			"foreign_account_provider_id", account.ProviderID,
		)
	}

	data := &loginSession{
		UserID:    user.ID,
		Name:      user.Name,
		Email:     user.Email,
		AvatarURL: user.AvatarURL,
	}
	g.SessionStore.Encode(w, sessionKeyLoginSession, data, g.LoginSessionMaxAge)

	g.Log.Info("User is logged in with google provider.", "user_id", user.ID)

	http.Redirect(w, r, g.SuccessRedirect, http.StatusSeeOther)
}

func (g *GoogleAuthRedirectHandler) Error(w http.ResponseWriter, r *http.Request, status int, message string) {
	var redirect string
	g.SessionStore.DecodeAndRemove(w, r, sessionKeyGoogleAuthErrorRedirect, &redirect)

	if redirect == "" {
		renderErrorPage(w, errorPageData{
			Status:  status,
			Message: message,
		})
		return
	}

	flash := newFlash(flashLevelError, message)
	g.SessionStore.Encode(w, sessionKeyFlash, flash, flashMaxAge)
	http.Redirect(w, r, redirect, http.StatusSeeOther)
}

type LogoutHandler struct {
	Log             *slog.Logger
	SessionStore    *CookieSessionStore
	SuccessRedirect string
}

func (l *LogoutHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var login *loginSession
	l.SessionStore.DecodeAndRemove(w, r, sessionKeyLoginSession, &login)
	l.Log.Debug("User logged out.", "user_id", login.UserID)
	http.Redirect(w, r, l.SuccessRedirect, http.StatusSeeOther)
}
