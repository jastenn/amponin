package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

var ErrNoSessionData = errors.New("no session data was stored with that key")

func NewCookieStore(secret string) *CookieStore {
	key := sha256.Sum256([]byte(secret))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		panic("unable to initialize a new cipher: " + err.Error())
	}

	return &CookieStore{
		Block: block,
	}
}

type CookieStore struct {
	Block cipher.Block
}

func (c *CookieStore) Encode(w http.ResponseWriter, key string, data any, maxAge time.Duration) error {
	var b bytes.Buffer
	err := gob.NewEncoder(&b).Encode(data)
	if err != nil {
		return fmt.Errorf("failed to encode data: %w", err)
	}

	iv := make([]byte, aes.BlockSize)
	_, err = io.ReadFull(rand.Reader, iv)
	if err != nil {
		return fmt.Errorf("unable to initialize IV: %w", err)
	}

	ciphertext := make([]byte, b.Len())
	cipher.NewCTR(c.Block, iv).XORKeyStream(ciphertext, b.Bytes())

	encoded := base64.RawURLEncoding.EncodeToString(append(iv, ciphertext...))

	cookie := &http.Cookie{
		Name:     key,
		Value:    encoded,
		Path:     "/",
		MaxAge:   int(maxAge.Seconds()),
		HttpOnly: true,
		Secure:   true,
	}
	http.SetCookie(w, cookie)

	return nil
}

func (c *CookieStore) Decode(w http.ResponseWriter, r *http.Request, key string, target any) error {
	cookie, err := r.Cookie(key)
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			return ErrNoSessionData
		}
		return fmt.Errorf("unable to retrieve cookie: %w", err)
	}

	decoded, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return fmt.Errorf("malformed data: invalid base64 data: %w", err)
	}

	iv := decoded[:aes.BlockSize]
	ciphertext := decoded[aes.BlockSize:]

	deciphered := make([]byte, len(ciphertext))
	cipher.NewCTR(c.Block, iv).XORKeyStream(deciphered, ciphertext)

	reader := bytes.NewReader([]byte(deciphered))
	err = gob.NewDecoder(reader).Decode(target)
	if err != nil {
		return fmt.Errorf("malformed data: invalid gob data: %w", err)
	}

	return nil
}

func (c *CookieStore) DecodeAndRemove(w http.ResponseWriter, r *http.Request, key string, target any) error {
	defer c.Remove(w, key)
	return c.Decode(w, r, key, target)
}

func (c *CookieStore) Remove(w http.ResponseWriter, key string) {
	http.SetCookie(w, &http.Cookie{
		Name:   key,
		MaxAge: -1,
	})
}

type FlashLevel string

const (
	FlashLevelError   FlashLevel = "toast_error"
	FlashLevelSuccess FlashLevel = "toast_success"
	FlashLevelWarn    FlashLevel = "toast_warn"
)

type Flash struct {
	Level   FlashLevel
	Message string
}

func (c *CookieStore) SetFlash(w http.ResponseWriter, message string, level FlashLevel) error {
	data := Flash{
		Message: message,
		Level:   level,
	}

	return c.Encode(w, "s_flash", data, time.Minute*5)
}

func (c *CookieStore) Flash(w http.ResponseWriter, r *http.Request) (*Flash, error) {
	data := &Flash{}
	err := c.DecodeAndRemove(w, r, "s_flash", &data)
	if err != nil {
		return nil, err
	}

	return data, nil
}
