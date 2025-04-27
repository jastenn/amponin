package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/gob"
	"fmt"
	"io"
	"net/http"
	"time"
)

type CookieSessionStore struct {
	block   cipher.Block
	options CookieSessionStoreOptions
}

type CookieSessionStoreOptions struct {
	Path string
}

func NewCookieSessionStore(secret string, options CookieSessionStoreOptions) *CookieSessionStore {
	secretHash := sha256.Sum256([]byte(secret))

	block, err := aes.NewCipher(secretHash[:])
	if err != nil {
		panic("unable to initialize cipher block: " + err.Error())
	}

	return &CookieSessionStore{
		block:   block,
		options: options,
	}
}

func (c *CookieSessionStore) Encode(w http.ResponseWriter, key string, data any, maxAge time.Duration) error {
	var b bytes.Buffer
	err := gob.NewEncoder(&b).Encode(data)
	if err != nil {
		return fmt.Errorf("Unable to encode data as gob: %w", err)
	}

	ciphertext := make([]byte, c.block.BlockSize()+b.Len())
	iv := ciphertext[:c.block.BlockSize()]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return fmt.Errorf("unable to generate initialization vector: %w", err)
	}

	stream := cipher.NewCFBEncrypter(c.block, iv)
	stream.XORKeyStream(ciphertext[c.block.BlockSize():], b.Bytes())

	encoded := base64.RawURLEncoding.EncodeToString(ciphertext)

	http.SetCookie(w, &http.Cookie{
		Name:   key,
		Value:  encoded,
		Path:   c.options.Path,
		MaxAge: int(maxAge.Seconds()),
	})

	return nil
}

func (c *CookieSessionStore) Decode(r *http.Request, key string, out any) error {
	cookie, err := r.Cookie(key)
	if err != nil {
		return fmt.Errorf("unable to retrieve cookie: %w", err)
	}

	b, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil {
		fmt.Errorf("unable to decode string: %w", err)
	}

	iv := b[:c.block.BlockSize()]
	ciphertext := b[c.block.BlockSize():]

	stream := cipher.NewCFBDecrypter(c.block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	err = gob.NewDecoder(bytes.NewReader(ciphertext)).Decode(out)
	if err != nil {
		return fmt.Errorf("unable to decode cipher into gob data: %w", err)
	}

	return nil
}

func (c *CookieSessionStore) Remove(w http.ResponseWriter, key string) {
	http.SetCookie(w, &http.Cookie{
		Name:   key,
		MaxAge: -1,
	})
}

func (c *CookieSessionStore) DecodeAndRemove(w http.ResponseWriter, r *http.Request, key string, out any) error {
	err := c.Decode(r, key, out)
	if err != nil {
		return err
	}

	c.Remove(w, key)
	return nil
}
