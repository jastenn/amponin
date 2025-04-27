package main

import (
	"embed"
	"time"
)

//go:embed templates/* static/*
var embedFS embed.FS

const (
	NanoidGenerator = "ABCDEFGHIJKLMNPQRSTUVWXYZ123456789"

	ClientMessageUnexpectedError = "Unexpected error occurred. Please try again later."

	SessionMaxAgeFlash = time.Minute * 10
	SessionKeyFlash    = "session_flash"
)

const (
	FlashLevelError   = "error"
	FlashLevelWarn    = "warn"
	FlashLevelSuccess = "success"
	FlashLevelInfo    = "info"
)

type Flash struct {
	Level   string
	Message string
}
