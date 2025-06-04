package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/mail"
	"strings"
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
	Avatar    *Image
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
	Avatar     *Image
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
	Avatar    *Image
	ExpiresAt time.Time

	EmailChangeState *loginSessionEmailChangeState
}

type loginSessionEmailChangeState struct {
	ExpiresAt  time.Time
	IsVerified bool
	NewEmail   string
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
			err = s.MailSender.SendMail(context.TODO(), fieldValues.Email, b.Bytes())
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
			Avatar:    user.Avatar,
			ExpiresAt: time.Now().Add(l.LoginSessionMaxAge),
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
			Avatar: &Image{
				Provider: ImageProviderForeign,
				URL:      result.Picture,
			},
			Name:  result.Name,
			Email: result.Email,
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
		Avatar:    user.Avatar,
		ExpiresAt: time.Now().Add(g.LoginSessionMaxAge),
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

type AccountHandler struct {
	Log                *slog.Logger
	SessionStore       *CookieSessionStore
	LocalAccountGetter localAccountGetter
}

type accountPageData struct {
	basePageData
	Flash          *flash
	IsLocalAccount bool
}

var accountPage = template.Must(
	template.New("account.html").
		Funcs(template.FuncMap{
			"redact_email": redactEmail,
		}).
		ParseFS(embedFS, "templates/pages/account/index.html", "templates/pages/base.html"))

func (a *AccountHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var loginSessionData *loginSession
	a.SessionStore.Decode(r, sessionKeyLoginSession, &loginSessionData)

	if loginSessionData == nil {
		a.Log.Error("Unauthenticated request.")
		renderErrorPage(w, errorPageData{
			Status:  http.StatusUnauthorized,
			Message: "Unauthenticated. Please login first.",
		})
		return
	}

	localAccount, _, err := a.LocalAccountGetter.GetLocalAccount(r.Context(), loginSessionData.Email)
	if err != nil && !errors.Is(err, ErrNoAccount) {
		if errors.Is(err, ErrNoUser) {
			a.Log.Debug("User no longer exists.")
			renderErrorPage(w, errorPageData{
				Status:  http.StatusBadRequest,
				Message: "User no longer exists.",
			})
			return
		}
		a.Log.Error("Unable to get local account.", "error", err.Error())
		renderErrorPage(w, errorPageData{
			Status:  http.StatusInternalServerError,
			Message: clientMessageUnexpectedError,
		})
		return
	}

	var flashData *flash
	a.SessionStore.DecodeAndRemove(w, r, sessionKeyFlash, &flashData)

	err = RenderPage(w, accountPage, http.StatusOK, accountPageData{
		basePageData: basePageData{
			LoginSession: loginSessionData,
		},
		Flash:          flashData,
		IsLocalAccount: localAccount != nil,
	})
	if err != nil {
		a.Log.Error("Unable to render page.", "error", err.Error())
		renderErrorPage(w, errorPageData{
			basePageData: basePageData{
				LoginSession: loginSessionData,
			},
			Status:  http.StatusInternalServerError,
			Message: clientMessageUnexpectedError,
		})
		return
	}
}

func redactEmail(s string) string {
	if s == "" {
		return ""
	}

	parts := strings.Split(s, "@")
	if len(parts) != 2 {
		panic("unable to parse email")
	}

	parts[0] = fmt.Sprintf("%c*******", parts[0][0])

	return strings.Join(parts, "@")
}

type AccountInfoUpdateHandler struct {
	Log                *slog.Logger
	SessionStore       *CookieSessionStore
	ImageStore         *LocalImageStore
	UserUpdater        userUpdater
	SuccessRedirectURL string
}

type UserUpdateData struct {
	Name   *string
	Email  *string
	Avatar *Image
}

type userUpdater interface {
	UpdateUser(ctx context.Context, userID string, data UserUpdateData) (*User, error)
}

type accountInfoUpdatePageData struct {
	basePageData
	Flash       *flash
	FieldValues accountInfoUpdateValues
	FieldErrors accountInfoUpdateErrors
}

type accountInfoUpdateValues struct {
	Name   string
	Avatar *multipart.FileHeader
}

type accountInfoUpdateErrors struct {
	Name   string
	Avatar string
}

var accountInfoUpdatePage = template.Must(template.ParseFS(embedFS, "templates/pages/account/update_info.html", "templates/pages/base.html"))

func (a *AccountInfoUpdateHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var loginSessionData *loginSession
	a.SessionStore.Decode(r, sessionKeyLoginSession, &loginSessionData)

	if loginSessionData == nil {
		a.Log.Error("Unauthenticated request.")
		renderErrorPage(w, errorPageData{
			Status:  http.StatusUnauthorized,
			Message: "Unauthenticated. Please login first.",
		})
		return
	}

	if r.Method == http.MethodPost {
		_, fh, err := r.FormFile("avatar")
		if err != nil && !errors.Is(err, http.ErrMissingFile) {
			a.Log.Error("Unable to parse avatar field.", "error", err.Error())
			a.renderPage(w, http.StatusInternalServerError, accountInfoUpdatePageData{
				basePageData: basePageData{
					LoginSession: loginSessionData,
				},
				Flash: newFlash(flashLevelError, clientMessageUnexpectedError),
			})
			return
		}

		var fieldErrors accountInfoUpdateErrors
		fieldValues := accountInfoUpdateValues{
			Name:   r.FormValue("name"),
			Avatar: fh,
		}

		var avatar *Image
		if fieldValues.Avatar != nil {
			var err error
			avatar, err = a.ImageStore.Store(fieldValues.Avatar)
			if err != nil {
				a.Log.Debug("Unable to store avatar.", "error", err.Error())
				fieldErrors.Avatar = "Unable to upload avatar."
				a.renderPage(w, http.StatusInternalServerError, accountInfoUpdatePageData{
					basePageData: basePageData{
						LoginSession: loginSessionData,
					},
					FieldErrors: fieldErrors,
				})
				return
			}
		}

		if l := len(fieldValues.Name); l == 0 {
			fieldErrors.Name = "Please fill out this field."
		} else if l == 1 {
			fieldErrors.Name = "Value is too short."
		} else if l > 18 {
			fieldErrors.Name = "Value is too long. It must not exceed 18 characters long."
		}

		if fieldErrors.Avatar != "" || fieldErrors.Name != "" {
			a.Log.Debug("Field validation failed.", "field_errors", fieldErrors)
			a.renderPage(w, http.StatusUnprocessableEntity, accountInfoUpdatePageData{
				basePageData: basePageData{
					LoginSession: loginSessionData,
				},
				FieldValues: fieldValues,
				FieldErrors: fieldErrors,
			})
			return
		}

		user, err := a.UserUpdater.UpdateUser(r.Context(), loginSessionData.UserID, UserUpdateData{
			Name:   &fieldValues.Name,
			Avatar: avatar,
		})
		if err != nil {
			a.Log.Error("Unable to update user.", "error", err.Error())
			a.renderPage(w, http.StatusInternalServerError, accountInfoUpdatePageData{
				basePageData: basePageData{
					LoginSession: loginSessionData,
				},
				Flash:       newFlash(flashLevelError, clientMessageUnexpectedError),
				FieldValues: fieldValues,
			})
			return
		}

		loginSessionData.Avatar = user.Avatar
		loginSessionData.Name = user.Name

		expires := loginSessionData.ExpiresAt.Sub(time.Now())
		err = a.SessionStore.Encode(w, sessionKeyLoginSession, loginSessionData, expires)
		if err != nil {
			a.Log.Error("Failed to update login session data.", "error", err.Error())
		}

		a.Log.Info("User info was successfully updated.", "user_id", user.ID)

		flash := newFlash(flashLevelSuccess, "User info was updated successfully.")
		a.SessionStore.Encode(w, sessionKeyFlash, flash, flashMaxAge)

		http.Redirect(w, r, a.SuccessRedirectURL, http.StatusFound)
		return
	}

	a.renderPage(w, http.StatusOK, accountInfoUpdatePageData{
		basePageData: basePageData{
			LoginSession: loginSessionData,
		},
		FieldValues: accountInfoUpdateValues{
			Name: loginSessionData.Name,
		},
	})
}

func (a *AccountInfoUpdateHandler) renderPage(w http.ResponseWriter, status int, data accountInfoUpdatePageData) {
	err := RenderPage(w, accountInfoUpdatePage, http.StatusOK, data)
	if err != nil {
		a.Log.Error("Unable to render page.", "error", err.Error())
		renderErrorPage(w, errorPageData{
			basePageData: basePageData{
				LoginSession: data.LoginSession,
			},
			Status:  http.StatusInternalServerError,
			Message: clientMessageUnexpectedError,
		})
		return
	}
}

type AccountChangeEmailRequestHandler struct {
	Log                *slog.Logger
	SessionStore       *CookieSessionStore
	MailSender         MailSender
	SuccessRedirectURL string
	ErrorRedirectURL   string
}

type accountChangeEmailRequestPageData struct {
	basePageData
	Flash *flash
	Code  string
	Error string
}

var accountChangeEmailRequestPage = template.Must(template.ParseFS(embedFS, "templates/pages/account/change_email_request.html", "templates/pages/base.html"))

var sessionKeyChangeEmailRequestVerification = "session_change_email_request_verification"

func (a *AccountChangeEmailRequestHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var loginSessionData *loginSession
	a.SessionStore.Decode(r, sessionKeyLoginSession, &loginSessionData)

	if loginSessionData == nil {
		a.Log.Error("Unauthorized. User is not logged in.")
		renderErrorPage(w, errorPageData{
			Status:  http.StatusUnauthorized,
			Message: "Unauthorized. Please login first.",
		})
		return
	}

	if r.Method == http.MethodPost {
		var correctVerificationCode string
		a.SessionStore.Decode(r, sessionKeyChangeEmailRequestVerification, &correctVerificationCode)

		verificationCode := r.FormValue("verification-code")
		var errorMessage string
		if verificationCode == "" {
			errorMessage = "Please fill out this field."
		}
		if errorMessage == "" && verificationCode != correctVerificationCode {
			errorMessage = "Verification code is invalid."
		}

		if errorMessage != "" {
			a.Log.Debug("Verification code validation failed.", "validation_error", errorMessage)
			a.renderPage(w, http.StatusUnprocessableEntity, accountChangeEmailRequestPageData{
				basePageData: basePageData{
					LoginSession: loginSessionData,
				},
				Code:  verificationCode,
				Error: errorMessage,
			})
			return
		}

		loginSessionData.EmailChangeState = &loginSessionEmailChangeState{
			ExpiresAt:  time.Now().Add(time.Minute * 5),
			IsVerified: true,
		}
		err := a.SessionStore.Encode(w, sessionKeyLoginSession, loginSessionData, loginSessionData.ExpiresAt.Sub(time.Now()))
		if err != nil {
			a.Log.Error("Unable to encode verification code to session store.", "error", err.Error())
			flashData := newFlash(flashLevelError, clientMessageUnexpectedError)
			a.SessionStore.Encode(w, sessionKeyFlash, flashData, flashMaxAge)
			http.Redirect(w, r, a.ErrorRedirectURL, http.StatusSeeOther)
			return
		}

		a.Log.Info("Email change verification successful.", "user_id", loginSessionData.UserID)
		http.Redirect(w, r, a.SuccessRedirectURL, http.StatusSeeOther)
		return
	}

	verificationCode := nanoid.MustGenerate(nanoidGenerator, 6)

	err := a.SessionStore.Encode(w, sessionKeyChangeEmailRequestVerification, verificationCode, time.Minute*5)
	if err != nil {
		a.Log.Error("Unable to encode verification code to session.", "error", err.Error())
		flashData := newFlash(flashLevelError, clientMessageUnexpectedError)
		a.SessionStore.Encode(w, sessionKeyFlash, flashData, flashMaxAge)
		http.Redirect(w, r, a.ErrorRedirectURL, http.StatusSeeOther)
		return
	}

	var b bytes.Buffer
	fmt.Fprintln(&b, "Subject: Email Update Verification")
	fmt.Fprintln(&b, "Content-Type: text/html")
	fmt.Fprintln(&b, "")
	err = verificationEmail.Execute(&b, verificationEmailData{
		Name:    loginSessionData.Name,
		Message: "We received a request to change the email address of your account.",
		Code:    verificationCode,
	})
	if err != nil {
		a.Log.Error("Unable to execute confirmation mail template.", "error", err.Error())
		renderErrorPage(w, errorPageData{
			Status:  http.StatusInternalServerError,
			Message: clientMessageUnexpectedError,
		})
		return
	}

	go func() {
		err := a.MailSender.SendMail(context.TODO(), loginSessionData.Email, b.Bytes())
		if err != nil {
			a.Log.Error("Unable to send mail.", "error", err.Error())
		}
	}()

	a.renderPage(w, http.StatusOK, accountChangeEmailRequestPageData{
		basePageData: basePageData{
			LoginSession: loginSessionData,
		},
		Flash: newFlash(flashLevelSuccess, "A verification code was sent on your email."),
	})
}

func (a *AccountChangeEmailRequestHandler) renderPage(w http.ResponseWriter, status int, data accountChangeEmailRequestPageData) {
	err := RenderPage(w, accountChangeEmailRequestPage, status, data)
	if err != nil {
		a.Log.Error("Unable to render page.", "error", err.Error())
		renderErrorPage(w, errorPageData{
			basePageData: data.basePageData,
			Status:       status,
			Message:      clientMessageUnexpectedError,
		})
		return
	}
}

type AccountEmailChangeHandler struct {
	Log                     *slog.Logger
	SessionStore            *CookieSessionStore
	ErrorRedirectURL        string
	VerificationRedirectURL string
	MailSender              MailSender
}

type accountEmailChangePageData struct {
	basePageData
	Flash    *flash
	NewEmail string
	Error    string
}

var accountEmailChangePage = template.Must(template.ParseFS(embedFS, "templates/pages/account/change_email.html", "templates/pages/base.html"))

var sessionKeyNewEmailVerificationCode = "session_key_new_email_verification"

func (a *AccountEmailChangeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var loginSessionData *loginSession
	a.SessionStore.Decode(r, sessionKeyLoginSession, &loginSessionData)
	if loginSessionData == nil {
		a.Log.Error("Unauthorized. User is not logged in.")
		renderErrorPage(w, errorPageData{
			basePageData: basePageData{
				LoginSession: loginSessionData,
			},
			Status:  http.StatusUnauthorized,
			Message: "Unathorized. Please login first.",
		})
		return
	}

	if !loginSessionData.EmailChangeState.IsVerified {
		a.Log.Debug("Unauthorized email change.")
		flashData := newFlash(flashLevelError, "Unauthorized. Please complete the verification step.")
		a.SessionStore.Encode(w, sessionKeyFlash, flashData, flashMaxAge)
		http.Redirect(w, r, a.ErrorRedirectURL, http.StatusSeeOther)
		return
	}

	if loginSessionData.EmailChangeState.ExpiresAt.Before(time.Now()) {
		a.Log.Debug("Verification code is expired.", "verification_code_expiry", loginSessionData.EmailChangeState.ExpiresAt.String())
		flashData := newFlash(flashLevelError, "Verification code is expired. Please try again.")
		a.SessionStore.Encode(w, sessionKeyFlash, flashData, flashMaxAge)
		http.Redirect(w, r, a.ErrorRedirectURL, http.StatusSeeOther)
		return
	}

	if r.Method == http.MethodPost {
		newEmail := r.FormValue("new-email")

		var validationError string
		if newEmail == "" {
			validationError = "Please fill out this field."
		}
		if _, err := mail.ParseAddress(newEmail); validationError == "" && err != nil {
			validationError = "Invalid email."
		}
		if validationError != "" {
			a.Log.Debug("New email fails validation.", "validation_error", validationError)
			a.renderPage(w, http.StatusUnprocessableEntity, accountEmailChangePageData{
				basePageData: basePageData{
					LoginSession: loginSessionData,
				},
				NewEmail: newEmail,
				Error:    validationError,
			})
			return
		}

		loginSessionData.EmailChangeState.ExpiresAt = time.Now().Add(time.Minute * 5)
		loginSessionData.EmailChangeState.NewEmail = newEmail

		err := a.SessionStore.Encode(w, sessionKeyLoginSession, loginSessionData, loginSessionData.ExpiresAt.Sub(time.Now()))
		if err != nil {
			a.Log.Error("Failed to update login session data")
			flashData := newFlash(flashLevelError, clientMessageUnexpectedError)
			a.SessionStore.Encode(w, sessionKeyFlash, flashData, flashMaxAge)
			http.Redirect(w, r, a.ErrorRedirectURL, http.StatusSeeOther)
			return
		}

		verificationCode := nanoid.MustGenerate(nanoidGenerator, 6)

		err = a.SessionStore.Encode(w, sessionKeyNewEmailVerificationCode, verificationCode, time.Minute*5)
		if err != nil {
			a.Log.Error("Unable to encode verification code to session.", "error", err.Error())
			flashData := newFlash(flashLevelError, clientMessageUnexpectedError)
			a.SessionStore.Encode(w, sessionKeyFlash, flashData, flashMaxAge)
			http.Redirect(w, r, a.ErrorRedirectURL, http.StatusSeeOther)
			return
		}

		var b bytes.Buffer
		fmt.Fprintln(&b, "Subject: Verify Your New Email Address for Amponin")
		fmt.Fprintln(&b, "Content-Type: text/html")
		fmt.Fprintln(&b, "")

		err = verificationEmail.Execute(&b, verificationEmailData{
			Name:    loginSessionData.Name,
			Message: "You're receiving this because a request was made to change your account's email address to this one.",
			Code:    verificationCode,
		})
		if err != nil {
			a.Log.Error("Unable to write email template.", "error", err.Error())
			flashData := newFlash(flashLevelError, clientMessageUnexpectedError)
			a.SessionStore.Encode(w, sessionKeyFlash, flashData, flashMaxAge)
			http.Redirect(w, r, a.ErrorRedirectURL, http.StatusSeeOther)
			return
		}

		go func() {
			err := a.MailSender.SendMail(context.TODO(), newEmail, b.Bytes())
			if err != nil {
				a.Log.Error("Unable to send mail.", "error", err.Error())
			}
		}()

		a.Log.Info("Verification code was sent on new email.", "new_email", newEmail)

		flashData := newFlash(flashLevelSuccess, "A verification code was sent on your new email.")
		a.SessionStore.Encode(w, sessionKeyFlash, flashData, flashMaxAge)

		http.Redirect(w, r, a.VerificationRedirectURL, http.StatusSeeOther)
		return
	}

	var flashData *flash
	a.SessionStore.DecodeAndRemove(w, r, sessionKeyFlash, &flashData)

	a.renderPage(w, http.StatusOK, accountEmailChangePageData{
		basePageData: basePageData{
			LoginSession: loginSessionData,
		},
		Flash: flashData,
	})
}

func (a *AccountEmailChangeHandler) renderPage(w http.ResponseWriter, status int, data accountEmailChangePageData) {
	err := RenderPage(w, accountEmailChangePage, status, data)
	if err != nil {
		a.Log.Error("Unable to render page.", "error", err.Error())
		renderErrorPage(w, errorPageData{
			basePageData: data.basePageData,
			Status:       status,
			Message:      clientMessageUnexpectedError,
		})
		return
	}
}

type AccountChangeEmailVerificationHandler struct {
	Log                *slog.Logger
	SessionStore       *CookieSessionStore
	UserUpdateData     userUpdater
	ErrorRedirectURL   string
	SuccessRedirectURL string
}

type accountChangeEmailVerificationPageData struct {
	basePageData
	Flash *flash
	Code  string
	Error string
}

var accountChangeEmailVerificationPage = template.Must(template.ParseFS(embedFS, "templates/pages/account/change_email_verification.html", "templates/pages/base.html"))

func (a *AccountChangeEmailVerificationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var loginSessionData *loginSession
	a.SessionStore.Decode(r, sessionKeyLoginSession, &loginSessionData)
	if loginSessionData == nil {
		a.Log.Error("Unauthorized. User is not logged in.")
		renderErrorPage(w, errorPageData{
			basePageData: basePageData{
				LoginSession: loginSessionData,
			},
			Status:  http.StatusUnauthorized,
			Message: "Unathorized. Please login first.",
		})
		return
	}

	if !loginSessionData.EmailChangeState.IsVerified {
		a.Log.Debug("Unauthorized email change.")
		flashData := newFlash(flashLevelError, "Unauthorized. Please complete the verification step.")
		a.SessionStore.Encode(w, sessionKeyFlash, flashData, flashMaxAge)
		http.Redirect(w, r, a.ErrorRedirectURL, http.StatusSeeOther)
		return
	}

	if loginSessionData.EmailChangeState.ExpiresAt.Before(time.Now()) {
		a.Log.Debug("Verification code is expired.", "verification_code_expiry", loginSessionData.EmailChangeState.ExpiresAt.String())
		flashData := newFlash(flashLevelError, "Verification code is expired. Please try again.")
		a.SessionStore.Encode(w, sessionKeyFlash, flashData, flashMaxAge)
		http.Redirect(w, r, a.ErrorRedirectURL, http.StatusSeeOther)
		return
	}

	if r.Method == http.MethodPost {
		newEmail := loginSessionData.EmailChangeState.NewEmail
		var correctVerificationCode string
		err := a.SessionStore.Decode(r, sessionKeyNewEmailVerificationCode, &correctVerificationCode)
		if err != nil {
			a.Log.Error("Unable to decode verification code from session.", "error", err.Error())
			flashData := newFlash(flashLevelError, clientMessageUnexpectedError)
			a.SessionStore.Encode(w, sessionKeyFlash, flashData, flashMaxAge)
			http.Redirect(w, r, a.ErrorRedirectURL, http.StatusSeeOther)
			return
		}

		verificationCode := r.FormValue("verification-code")
		var validationError string
		if verificationCode == "" {
			validationError = "Please fill out this field."
		}
		if validationError == "" && verificationCode != correctVerificationCode {
			validationError = "Verification code is invalid."
		}

		if validationError != "" {
			a.Log.Debug("Verification code failed validation.", "validation_error", validationError)
			a.renderPage(w, http.StatusUnprocessableEntity, accountChangeEmailVerificationPageData{
				basePageData: basePageData{
					LoginSession: loginSessionData,
				},
				Code:  verificationCode,
				Error: validationError,
			})
			return
		}

		user, err := a.UserUpdateData.UpdateUser(r.Context(), loginSessionData.UserID, UserUpdateData{
			Email: &newEmail,
		})
		if err != nil {
			var flashData *flash
			if errors.Is(err, ErrUserEmailInUse) {
				a.Log.Debug("Email is already in use.", "email", newEmail)
				flashData = newFlash(flashLevelError, "Email is already in use.")

			} else {
				a.Log.Error("Unexpected error while updating user email.", "error", err.Error())
				flashData = newFlash(flashLevelError, clientMessageUnexpectedError)
			}
			a.SessionStore.Encode(w, sessionKeyFlash, flashData, flashMaxAge)

			http.Redirect(w, r, a.ErrorRedirectURL, http.StatusSeeOther)
			return
		}

		a.Log.Info("Successfully changed email.", "user_id", user.ID, "new_email", newEmail, "old_email", loginSessionData.Email)

		loginSessionData.EmailChangeState = nil
		loginSessionData.Email = newEmail

		err = a.SessionStore.Encode(w, sessionKeyLoginSession, loginSessionData, loginSessionData.ExpiresAt.Sub(time.Now()))
		if err != nil {
			a.Log.Error("Unable to update login session data.", "error", err.Error())
		}

		flashData := newFlash(flashLevelSuccess, "Change email was successful.")
		a.SessionStore.Encode(w, sessionKeyFlash, flashData, flashMaxAge)

		http.Redirect(w, r, a.SuccessRedirectURL, http.StatusSeeOther)

		return
	}

	var flashData *flash
	a.SessionStore.DecodeAndRemove(w, r, sessionKeyFlash, &flashData)

	a.renderPage(w, http.StatusOK, accountChangeEmailVerificationPageData{
		basePageData: basePageData{
			LoginSession: loginSessionData,
		},
		Flash: flashData,
	})
}

func (a *AccountChangeEmailVerificationHandler) renderPage(w http.ResponseWriter, status int, data accountChangeEmailVerificationPageData) {
	err := RenderPage(w, accountChangeEmailVerificationPage, status, data)
	if err != nil {
		a.Log.Error("Unable to render page.", "error", err.Error())
		renderErrorPage(w, errorPageData{
			basePageData: data.basePageData,
			Status:       http.StatusInternalServerError,
			Message:      clientMessageUnexpectedError,
		})
		return
	}
}
