package main

import (
	"context"
	"fmt"
	"net/smtp"
)

type MailSender interface {
	SendMail(ctx context.Context, address string, data []byte) error
}

type GoogleMailSender struct {
	auth smtp.Auth
	from string
}

func NewGoogleMailSender(address string, password string) *GoogleMailSender {
	auth := smtp.PlainAuth("", address, password, "smtp.gmail.com")

	return &GoogleMailSender{
		auth: auth,
		from: address,
	}
}

func (g *GoogleMailSender) SendMail(ctx context.Context, to string, msg []byte) error {
	err := smtp.SendMail("smtp.gmail.com:587", g.auth, g.from, []string{to}, msg)
	if err != nil {
		return fmt.Errorf("unable to send mail: %w", err)
	}

	return nil
}
