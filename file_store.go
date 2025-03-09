package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"time"

	nanoid "github.com/matoous/go-nanoid/v2"
)

var ErrFileExists = errors.New("file already exists")

type FileStore interface {
	Save(filepath string, file io.Reader) (url string, err error)
}

type LocalFileStore struct {
	BaseDir string
}

func (l *LocalFileStore) Save(filename string, file io.Reader) (url string, err error) {
	initialPath := filepath.Join(l.BaseDir, filename)
	_, err = os.Stat(initialPath)
	if errors.Is(err, os.ErrExist) {
		return "", ErrFileExists
	}

	dir, filename := filepath.Split(initialPath)
	err = os.MkdirAll(dir, os.ModePerm)
	if err != nil {
		return "", fmt.Errorf("unable to create directory for file to store in: %w", err)
	}

	filename = fmt.Sprintf("%v-%v", strconv.FormatInt(time.Now().UnixMicro(), 10), nanoid.Must(4)+filename)

	b, err := io.ReadAll(file)
	if err != nil {
		return "", fmt.Errorf("failed to save file: unable to read file: %w", err)
	}

	finalPath := path.Join(dir, filename)
	err = os.WriteFile(finalPath, b, os.ModePerm)
	if err != nil {
		return "", fmt.Errorf("failed to save file: unable to write file: %w", err)
	}

	return "/" + finalPath, nil
}
