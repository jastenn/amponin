package main

import (
	"net/http"
	"sync"

	"github.com/go-chi/chi/v5"
	"github.com/jastenn/amponin/internal/pkg/oidc/google"
)

// UsersHandler is a http handler for creating and managing users
type UsersHandler struct {
	sync.Once
	r                     http.Handler
	googleIDTokenVerifier *google.IDTokenVerifier
}

func NewUsersHandler(googleIDTokenVerifier *google.IDTokenVerifier) *UsersHandler {
	return &UsersHandler{
		googleIDTokenVerifier: googleIDTokenVerifier,
	}
}

func (u *UsersHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u.Once.Do(func() {
		r := chi.NewMux()

		r.Post("/signup/google", u.SignupUserWithGoogle)

		u.r = r
	})

	u.r.ServeHTTP(w, r)
}

// SignupWithGoogle creates a new user with the Google issued ID token and the
// informations provided on request body.
func (u *UsersHandler) SignupUserWithGoogle(w http.ResponseWriter, r *http.Request) {
	var data struct {
		IDToken string `json:"id_token"`
	}
	err := readJSON(r, &data)
	if err != nil {
		writeJSON(
			w, http.StatusBadRequest, nil,
			H{
				"error": err.Error(),
			},
		)
		return
	}

	claims, err := u.googleIDTokenVerifier.VerifyAndParseClaims(r.Context(), data.IDToken)
	if err != nil {
		writeJSON(
			w, http.StatusBadRequest, nil,
			H{
				"error": err.Error(),
			},
		)
		return
	}

	writeJSON(
		w, http.StatusOK, nil,
		H{
			"claims": claims,
		},
	)
}


