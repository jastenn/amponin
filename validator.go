package main

import (
	"net/mail"
	"time"
)

type FieldValidation struct {
	FieldErrors map[string]string
}

func NewFieldValidation() *FieldValidation {
	return &FieldValidation{
		FieldErrors: make(map[string]string),
	}
}

func (f *FieldValidation) Check(condition bool, key string, message string) {
	if !condition {
		return
	}

	f.Add(key, message)
}

func (f *FieldValidation) Valid() bool {
	return len(f.FieldErrors) == 0
}

func (f *FieldValidation) Add(key, message string) {
	_, ok := f.FieldErrors[key]
	if ok {
		return
	}

	f.FieldErrors[key] = message
}

func IsInvalidEmail(email string) bool {
	_, err := mail.ParseAddress(email)

	return err != nil || len(email) > 254
}

func IsInvalidCoordinates(s string) bool {
	_, err := ParseCoordinates(s)
	return err != nil
}

func IsInvalidDate(s string) bool {
	_, err := time.Parse(time.DateOnly, s)
	return err != nil
}
