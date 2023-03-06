package oidc

import "errors"

var (
	ErrIDTokenInvalid = errors.New("invalid id token")
	ErrIDTokenExpired = errors.New("expired id token")
)
