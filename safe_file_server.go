package main

import (
	"io/fs"
	"net/http"
	"os"
)

func NewSafeFileServer(fs http.FileSystem) http.Handler {
	return http.FileServer(&SafeHTTPFileSystem{
		FS: fs,
	})
}

type SafeHTTPFileSystem struct {
	FS http.FileSystem
}

func (f *SafeHTTPFileSystem) Open(name string) (http.File, error) {
	file, err := f.FS.Open(name)
	if err != nil {
		return nil, err
	}

	return FileOnlyHTTPFile{file}, nil
}

type FileOnlyHTTPFile struct {
	http.File
}

func (n FileOnlyHTTPFile) Stat() (fs.FileInfo, error) {
	fileInfo, err := n.File.Stat()
	if err != nil {
		return fileInfo, err
	}

	if fileInfo.IsDir() {
		return nil, os.ErrNotExist
	}

	return fileInfo, err
}
