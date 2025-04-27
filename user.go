package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/mail"
	"time"

	nanoid "github.com/matoous/go-nanoid/v2"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID        string
	Name      string
	Email     string
	AvatarURL *string
	CreatedAt time.Time
	UpdatedAt time.Time
}

type LocalAccount struct {
	ID           string
	PasswordHash []byte
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

const SessionKeySignupVerificationData = "session_signup_verification"

type SessionSignupVerificationData struct {
	SignupValues
	VerificationCode string
}

type SignupHandler struct {
	Log                     *slog.Logger
	MailSender              MailSender
	SessionStore            *CookieSessionStore
	VerificationRedirectURL string
}

type SignupPageData struct {
	Flash       *Flash
	FieldValues SignupValues
	FieldErrors SignupErrors
}

type SignupValues struct {
	Name            string
	Email           string
	Password        string
	ConfirmPassword string
}

type SignupErrors struct {
	Name            string
	Email           string
	Password        string
	ConfirmPassword string
}

type VerificationEmailData struct {
	Name    string
	Message string
	Code    string
}

var signupPage = template.Must(template.ParseFS(embedFS, "templates/base.html", "templates/signup.html"))

var verificationEmail = template.Must(template.ParseFS(embedFS, "templates/email/verification.html"))

func (s *SignupHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		signupValues := SignupValues{
			Name:            r.FormValue("name"),
			Email:           r.FormValue("email"),
			Password:        r.FormValue("password"),
			ConfirmPassword: r.FormValue("confirm-password"),
		}

		signupErrors, valid := s.Validate(signupValues)
		if !valid {
			err := RenderPage(w, signupPage, http.StatusOK, SignupPageData{
				FieldValues: signupValues,
				FieldErrors: signupErrors,
			})
			if err != nil {
				s.Log.Error("Unable to render page.", "error", err.Error())
				RenderErrorPage(w, http.StatusInternalServerError, ClientMessageUnexpectedError)
				return
			}
			return
		}

		verificationCode := nanoid.MustGenerate(NanoidGenerator, 6)

		data := SessionSignupVerificationData{
			SignupValues:     signupValues,
			VerificationCode: verificationCode,
		}
		s.SessionStore.Encode(w, SessionKeySignupVerificationData, data, time.Minute*5)

		var b bytes.Buffer

		fmt.Fprintln(&b, "Subject: Please Confirm Your Email Address")
		fmt.Fprintln(&b, "Content-Type: text/html")
		fmt.Fprintln(&b, "")

		err := verificationEmail.Execute(&b, VerificationEmailData{
			Name:    signupValues.Name,
			Message: "Thanks for signing up.",
			Code:    verificationCode,
		})
		if err != nil {
			s.Log.Error("Unable to execute confirmation mail template.", "error", err.Error())
			RenderErrorPage(w, http.StatusInternalServerError, ClientMessageUnexpectedError)
			return
		}

		go func() {
			err = s.MailSender.SendMail(r.Context(), signupValues.Email, b.Bytes())
			if err != nil {
				s.Log.Error("Unable to send confirmation email.", "error", err.Error())
			}
		}()

		flash := &Flash{
			Level:   FlashLevelSuccess,
			Message: "Verification code sent.",
		}
		s.SessionStore.Encode(w, SessionKeyFlash, flash, SessionMaxAgeFlash)

		http.Redirect(w, r, s.VerificationRedirectURL, http.StatusSeeOther)
		return
	}

	var flash *Flash
	s.SessionStore.DecodeAndRemove(w, r, SessionKeyFlash, &flash)

	err := RenderPage(w, signupPage, http.StatusOK, SignupPageData{
		Flash: flash,
	})
	if err != nil {
		s.Log.Error("Unable to render page.", "error", err.Error())
		RenderErrorPage(w, http.StatusInternalServerError, ClientMessageUnexpectedError)
		return
	}
}

func (s *SignupHandler) Validate(signupValues SignupValues) (signupErrors SignupErrors, valid bool) {
	if l := len(signupValues.Name); l == 0 {
		signupErrors.Name = "Please fill out this field."
	} else if l == 1 {
		signupErrors.Name = "Value is too short."
	} else if l > 18 {
		signupErrors.Name = "Value is too long. It must not exceed 18 characters long."
	}

	if l := len(signupValues.Email); l == 0 {
		signupErrors.Email = "Please fill out this field."
	} else if _, err := mail.ParseAddress(signupValues.Email); l > 255 || err != nil {
		signupErrors.Email = "Value is invalid email."
	}

	if l := len(signupValues.Password); l == 0 {
		signupErrors.Password = "Please fill out this field."
	} else if l < 8 {
		signupErrors.Password = "Value is too short. It must be at least 8 characters long."
	} else if l > 32 {
		signupErrors.Password = "Value is too long. It must not exceed 32 characters long."
	}

	if signupValues.ConfirmPassword == "" {
		signupErrors.ConfirmPassword = "Please fill out this field."
	} else if signupValues.ConfirmPassword != signupValues.Password {
		signupErrors.ConfirmPassword = "Value doesn't match the password."
	}

	if signupErrors.Name != "" ||
		signupErrors.Email != "" ||
		signupErrors.Password != "" ||
		signupErrors.ConfirmPassword != "" {

		return signupErrors, false
	}

	return SignupErrors{}, true
}

type SignupVerificationHandler struct {
	Log                 *slog.Logger
	SessionStore        *CookieSessionStore
	LocalAccountCreator LocalAccountCreator
	SignupURL           string
}

type NewLocalAccount struct {
	Name         string
	Email        string
	PasswordHash []byte
}

var ErrEmailInUse = errors.New("email is already in use.")

type LocalAccountCreator interface {
	CreateLocalAccount(context.Context, NewLocalAccount) (*LocalAccount, *User, error)
}

type SignupVerificationPageData struct {
	Flash                 *Flash
	VerificationCode      string
	VerificationCodeError string
}

var signupVerificationTemplate = template.Must(template.ParseFS(embedFS, "templates/signup-verification.html", "templates/base.html"))

func (s *SignupVerificationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		verificationCode := r.FormValue("verification-code")

		var signupVerificationData SessionSignupVerificationData
		err := s.SessionStore.Decode(r, SessionKeySignupVerificationData, &signupVerificationData)
		if err != nil {
			s.Log.Error("Unable to decode signup verification data.", "error", err.Error())
			flash := &Flash{
				Level:   FlashLevelError,
				Message: "Please start the signup process.",
			}
			s.SessionStore.Encode(w, SessionKeyFlash, flash, SessionMaxAgeFlash)
			http.Redirect(w, r, s.SignupURL, http.StatusSeeOther)
			return
		}

		if signupVerificationData.VerificationCode != verificationCode {
			s.RenderPage(w, http.StatusOK, SignupVerificationPageData{
				VerificationCode:      verificationCode,
				VerificationCodeError: "Verification code is invalid.",
			})
			return
		}

		passwordHash, err := bcrypt.GenerateFromPassword([]byte(signupVerificationData.Password), bcrypt.DefaultCost)
		if err != nil {
			s.Log.Error("Unable to generate hash from password.", "error", err.Error())
			s.RenderPage(w, http.StatusOK, SignupVerificationPageData{
				Flash: &Flash{
					Level:   FlashLevelError,
					Message: ClientMessageUnexpectedError,
				},
				VerificationCode: verificationCode,
			})
			return
		}

		user, localAccount, err := s.LocalAccountCreator.CreateLocalAccount(r.Context(), NewLocalAccount{
			Name:         signupVerificationData.Name,
			Email:        signupVerificationData.Email,
			PasswordHash: passwordHash,
		})
		if err != nil {
			if errors.Is(err, ErrEmailInUse) {
				s.Log.Info("Email is already in use.", "email", signupVerificationData.Email)
				flash := &Flash{
					Level:   FlashLevelError,
					Message: "Email is already in use.",
				}
				s.SessionStore.Encode(w, SessionKeyFlash, flash, SessionMaxAgeFlash)
				http.Redirect(w, r, s.SignupURL, http.StatusSeeOther)
				return
			}

			s.Log.Error("Unable to create local account.", "error", err.Error())

			s.RenderPage(w, http.StatusOK, SignupVerificationPageData{
				Flash: &Flash{
					Level:   FlashLevelError,
					Message: ClientMessageUnexpectedError,
				},
				VerificationCode: verificationCode,
			})
			return
		}

		s.Log.Info("Successfully created a local account.", "user_id", user.ID, "local_account_id", localAccount.ID)
		flash := &Flash{
			Level:   FlashLevelSuccess,
			Message: "Successfully created an account.",
		}
		s.SessionStore.Encode(w, SessionKeyFlash, flash, SessionMaxAgeFlash)
		http.Redirect(w, r, s.SignupURL, http.StatusSeeOther)
		return
	}

	var flash *Flash
	s.SessionStore.Decode(r, SessionKeyFlash, &flash)

	s.RenderPage(w, http.StatusOK, SignupVerificationPageData{
		Flash: flash,
	})
}

func (s *SignupVerificationHandler) RenderPage(w http.ResponseWriter, status int, data SignupVerificationPageData) {
	err := RenderPage(w, signupVerificationTemplate, status, data)
	if err != nil {
		s.Log.Error("Unable to render page.", "error", err.Error())
		RenderErrorPage(w, http.StatusInternalServerError, ClientMessageUnexpectedError)
		return
	}
}
