package main

import (
	"context"
	"fmt"
	"net/smtp"
	"time"
)

func NewGoogleMailSender(email, password string) *GoogleMailSender {
	auth := smtp.PlainAuth("", email, password, "smtp.gmail.com")
	return &GoogleMailSender{
		Auth:   auth,
		Email:  email,
		MaxAge: time.Minute * 5,
	}
}

type GoogleMailSender struct {
	MaxAge time.Duration
	Email  string
	Auth   smtp.Auth
}

func (g *GoogleMailSender) SendMail(ctx context.Context, email string, msg []byte) error {
	err := smtp.SendMail("smtp.gmail.com:587", g.Auth, g.Email, []string{email}, msg)
	if err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}
