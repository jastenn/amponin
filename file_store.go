package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

var ErrFileExists = errors.New("file already exists.")

type LocalFileStore struct {
	BaseDir string
}

func (l *LocalFileStore) Save(filename string, file io.Reader) (url string, err error) {
	completeFilePath := filepath.Join(l.BaseDir, filename)
	_, err = os.Stat(completeFilePath)
	if errors.Is(err, os.ErrExist) {
		return "", ErrFileExists
	}

	dir, _ := filepath.Split(completeFilePath)
	err = os.MkdirAll(dir, os.ModePerm)
	if err != nil {
		return "", fmt.Errorf("unable to create directory for file to store in: %w", err)	
	}

	b, err := io.ReadAll(file)
	if err != nil {
		return "", fmt.Errorf("failed to save file: unable to read file: %w", err)
	}
	err = os.WriteFile(completeFilePath, b, os.ModePerm)
	if err != nil {
		return "", fmt.Errorf("failed to save file: unable to write file: %w", err)
	}

	return completeFilePath, nil
}
