package main

import (
	"errors"
	"time"
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

