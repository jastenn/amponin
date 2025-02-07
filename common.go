package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html/template"
	"io"

	"github.com/alexedwards/scs/v2"
)

const (
	SessionKeyLoginSession = "login_session"
	SessionKeyFlash        = "flash_message"
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

func PopSessionFlash(sm *scs.SessionManager, ctx context.Context) (*Flash, error) {
	data, ok := sm.Pop(ctx, SessionKeyFlash).(*Flash)
	if !ok {
		return nil, errors.New("unable to get flash message on session")
	}

	return data, nil
}

func PutSessionFlash(sm *scs.SessionManager, ctx context.Context, message string, level FlashLevel) {
	sm.Put(ctx, SessionKeyFlash, &Flash{
		Message: message,
		Level:   level,
	})
}

func PutSessionUser(sm *scs.SessionManager, ctx context.Context, data *SessionUser) {
	sm.Put(ctx, SessionKeyLoginSession, data)
}

func GetSessionUser(sm *scs.SessionManager, ctx context.Context) (*SessionUser, error) {
	data := &SessionUser{}
	data, ok := sm.Get(ctx, SessionKeyLoginSession).(*SessionUser)
	if !ok {
		return nil, errors.New("unable to get login session from session")
	}

	return data, nil
}

func RemoveSessionUser(sm *scs.SessionManager, ctx context.Context) *SessionUser {
	data, _ := GetSessionUser(sm, ctx)
	sm.Remove(ctx, SessionKeyLoginSession)
	return data
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
