package main

import (
	"fmt"
	"io"
	"mime/multipart"
	"os"
	"path"

	"github.com/google/uuid"
)

type LocalImageStore struct {
	BasePath string
}

func NewLocalImageStore(basePath string) *LocalImageStore {
	err := os.MkdirAll(basePath, os.ModePerm)
	if err != nil {
		panic("unable to create base directory of local image store: " + err.Error())
	}

	return &LocalImageStore{
		BasePath: basePath,
	}
}

func (l *LocalImageStore) StoreMultipart(files []*multipart.FileHeader) ([]Image, error) {
	var result []Image
	for _, file := range files {
		image, err := l.Store(file)
		if err != nil {
			return nil, err
		}

		result = append(result, *image)
	}

	return result, nil
}

func (l *LocalImageStore) Store(file *multipart.FileHeader) (*Image, error) {
	filepath := path.Join(l.BasePath, uuid.New().String())

	inputFile, err := file.Open()
	if err != nil {
		return nil, fmt.Errorf("unable to open file: %w", err)
	}

	outFile, err := os.Create(filepath)
	if err != nil {
		return nil, fmt.Errorf("unable to create file: %w", err)
	}
	_, err = io.Copy(outFile, inputFile)
	if err != nil {
		return nil, fmt.Errorf("unable to write file: %w", err)
	}

	return &Image{
		Provider: ImageProviderLocal,
		URL:      "/" + filepath,
	}, nil
}
