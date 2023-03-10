package usecase

import (
	"context"
	"errors"
	"time"

	"github.com/jastenn/amponin/internal/pkg/oidc"
	"github.com/jastenn/amponin/internal/pkg/oidc/google"
)

var (
	ErrAccountAlreadyUsed = errors.New("account is already in use")
	ErrUsernamelreadyUsed = errors.New("username is already in use")
	ErrTokenIDExpired     = oidc.ErrIDTokenExpired
	ErrTokenIDInvalid     = oidc.ErrIDTokenInvalid
)

type Avatar struct {
	Raw       string
	Thumbnail *string
}

type User struct {
	Username  string
	Email     string
	Verified  bool
	Picture   *Avatar
	Account   Account
	CreatedAt time.Time
	UpdatedAt time.Time
}

const (
	ProviderGoogle = "google"
)

type Account struct {
	ID        string
	Provider  string
	CreatedAt time.Time
	UpdatedAt time.Time
}

type UsersStore interface {
	Create(ctx context.Context, user User) error
}

type UsersService struct {
	usersStore            UsersStore
	googleIDTokenVerifier *google.IDTokenVerifier
}

func NewUsersService(usersStore UsersStore, googleIDTokenVerifier *google.IDTokenVerifier) *UsersService {
	return &UsersService{
		usersStore:            usersStore,
		googleIDTokenVerifier: googleIDTokenVerifier,
	}
}

func (u *UsersService) SignupWithGoogle(ctx context.Context, idToken string, username string) (User, error) {
	if username == "" {
		return User{}, errors.New("username is a required field")
	}
	claims, err := u.googleIDTokenVerifier.VerifyAndParseClaims(ctx, idToken)
	if err != nil {
		return User{}, err
	}

	user := User{
		Username:  username,
		Email:     claims.Email,
		Verified:  claims.Verified,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Account: Account{
			ID:        claims.ID,
			Provider:  ProviderGoogle,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
	}
	if claims.Picture != nil {
		user.Picture = &Avatar{
			Raw: *claims.Picture,
		}
	}

	err = u.usersStore.Create(ctx, user)
	if err != nil {
		return User{}, err
	}

	return user, nil
}
