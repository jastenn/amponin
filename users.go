package main

import (
	"errors"
	"net/http"
	"sync"

	"github.com/go-chi/chi/v5"
	"github.com/jastenn/amponin/internal/usecase"
)

// UsersHandler is a http handler for creating and managing users
type UsersHandler struct {
	sync.Once
	r            http.Handler
	usersService *usecase.UsersService
}

func NewUsersHandler(usersService *usecase.UsersService) *UsersHandler {
	return &UsersHandler{
		usersService: usersService,
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
		IDToken  string `json:"id_token"`
		Username string `json:"username"`
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

	user, err := u.usersService.SignupWithGoogle(r.Context(), data.IDToken, data.Username)
	if err != nil {
		switch {
		case errors.Is(err, usecase.ErrAccountAlreadyUsed) ||
			errors.Is(err, usecase.ErrUsernamelreadyUsed) ||
			errors.Is(err, usecase.ErrTokenIDExpired) ||
			errors.Is(err, usecase.ErrTokenIDInvalid):
			writeJSON(
				w, http.StatusBadRequest, nil,
				H{
					"error": err.Error(),
				},
			)
		default:
			panic(err)
		}
		return
	}

	writeJSON(
		w, http.StatusOK, nil,
		H{
			"user": user,
		},
	)
}
