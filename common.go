package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"strings"

	"github.com/alexedwards/scs/v2"

	nanoid "github.com/matoous/go-nanoid/v2"
)

const (
	SessionKeyUser  = "login_session"
	SessionKeyFlash = "flash_message"
)

type FlashLevel string

const (
	FlashLevelError   FlashLevel = "flash_error"
	FlashLevelWarn    FlashLevel = "flash_warn"
	FlashLevelSuccess FlashLevel = "flash_success"
)

type Flash struct {
	Message string
	Level   FlashLevel
}

func NewFlash(message string, level FlashLevel) *Flash {
	return &Flash{
		Message: message,
		Level:   level,
	}
}

func NewErrorFlash(message string) *Flash {
	return &Flash{
		Message: message,
		Level:   FlashLevelError,
	}
}

func PopSessionFlash(sm *scs.SessionManager, ctx context.Context) (*Flash, error) {
	data, ok := sm.Pop(ctx, SessionKeyFlash).(*Flash)
	if !ok {
		return nil, errors.New("unable to get flash message on session")
	}

	return data, nil
}

type SessionUser struct {
	UserID      string
	DisplayName string
	AvatarURL   *string
}

func GetSessionUser(sm *scs.SessionManager, ctx context.Context) (*SessionUser, error) {
	data := &SessionUser{}
	data, ok := sm.Get(ctx, SessionKeyUser).(*SessionUser)
	if !ok {
		return nil, errors.New("unable to get login session from session")
	}

	return data, nil
}

type BasePage struct {
	SessionUser *SessionUser
}

func ExecuteTemplate(tpl *template.Template, w io.Writer, name string, data any) error {
	var b bytes.Buffer
	err := tpl.ExecuteTemplate(&b, name, data)
	if err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}

	_, err = io.Copy(w, &b)
	if err != nil {
		return fmt.Errorf("failed to write template: %w", err)
	}

	return nil
}

func GenerateVerificationCode() string {
	return nanoid.MustGenerate("abcdefghijklmnopqrstuvwxyz1234567890", 6)
}

func FormImage(r *http.Request, key string) (data []byte, filename string, err error) {
	f, fheader, err := r.FormFile(key)
	if err != nil {
		return nil, "", err
	}

	b, err := io.ReadAll(f)
	if err != nil {
		return nil, "", fmt.Errorf("unable to read form image: %w", err)
	}

	if !IsImage(b) {
		return nil, "", ErrUnexpectedFileType
	}

	return b, fheader.Filename, nil
}

type FormImageResult struct {
	Data     []byte
	Filename string
}

func FormImages(r *http.Request, key string) ([]FormImageResult, error) {
	hfiles := r.MultipartForm.File[key]

	var result []FormImageResult
	for _, hfile := range hfiles {
		f, err := hfile.Open()
		if err != nil {
			return nil, fmt.Errorf("unable to open one of the form image: %w", err)
		}

		b, err := io.ReadAll(f)
		if err != nil {
			return nil, fmt.Errorf("unable to read on of the form image: %w", err)
		}

		if !IsImage(b) {
			return nil, ErrUnexpectedFileType
		}

		result = append(result, FormImageResult{
			Filename: hfile.Filename,
			Data:     b,
		})
	}

	return result, nil
}

func IsImage(b []byte) bool {
	mimetype := http.DetectContentType(b)
	xfileType := strings.Split(mimetype, "/")
	return xfileType[0] == "image"
}

func BasicHTTPError(w http.ResponseWriter, status int) {
	http.Error(w, http.StatusText(status), status)
}
