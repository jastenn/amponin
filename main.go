package main

import (
	"bytes"
	"context"
	"embed"
	"flag"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"time"
)

//go:embed templates/*
//go:embed public/*
var embedFS embed.FS

func main() {
	address := flag.String("address", ":8080", "network address to bind on")
	writeTimeout := flag.Duration("write-timeout", time.Second*3, "timeout to use when writing response")
	readTimeout := flag.Duration("read-timeout", time.Second*2, "timeout to use when reading request")
	idleTimeout := flag.Duration("idle-timeout", time.Second*8, "timeout to use for idle connection")
	shutdownTimeout := flag.Duration("shutdown-timeout", time.Second*15, "timeout to use waiting for active connections before closing")
	certFile := flag.String("cert-file", "", "path to SSL Certificate to use for secure connection")
	keyFile := flag.String("key-file", "", "path to SSL Key to use for secure connection")
	flag.Parse()

	if *certFile == "" {
		panic("ssl-cert flag required")
	}
	if *keyFile == "" {
		panic("ssl-key flag required")
	}

	publicFS, err := fs.Sub(embedFS, "public")
	if err != nil {
		panic("unable to extract public fs from embedFS: " + err.Error())
	}

	templatesFS, err := fs.Sub(embedFS, "templates")
	if err != nil {
		panic("unable to extract templates fs from embedFS: " + err.Error())
	}

	log := slog.New(slog.NewTextHandler(
		os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		},
	))

	handler := http.NewServeMux()
	handler.Handle("GET /public/{filename...}", http.StripPrefix("/public", http.FileServerFS(publicFS)))
	handler.Handle("GET /", &IndexHandler{
		TemplateFS:      templatesFS,
		NotFoundHandler: http.NotFoundHandler(),
	})

	server := http.Server{
		Addr:         *address,
		Handler:      handler,
		ReadTimeout:  *readTimeout,
		WriteTimeout: *writeTimeout,
		IdleTimeout:  *idleTimeout,
	}

	errCh := make(chan error)
	go func() {
		log.Info("Server running.", "address", server.Addr)
		errCh <- server.ListenAndServeTLS(*certFile, *keyFile)
	}()
	defer log.Info("Server closed.")

	shutdownCh := make(chan os.Signal, 1)
	signal.Notify(shutdownCh, os.Interrupt)

	select {
	case err := <-errCh:
		log.Error("Unable to start server.", "reason", err.Error())
	case <-shutdownCh:
		log.Info("Shutdown signal received.")
		log.Info("Closing active connection gracefully.")

		ctx, cancel := context.WithTimeout(context.Background(), *shutdownTimeout)
		defer cancel()
		err := server.Shutdown(ctx)
		if err != nil {
			log.Error("Failed to shutdown server gracefully. Closing active connection immediately instead.", "reason", err.Error())
			server.Close()
		}
	}
}

type IndexHandler struct {
	NotFoundHandler http.Handler
	TemplateFS      fs.FS

	indexTemplate *template.Template
}

func (i *IndexHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	tpl := template.Must(template.ParseFS(i.TemplateFS, "index.html"))
	err := ExecuteTemplate(tpl, w, "index.html", nil)
	if err != nil {
		panic("IndexHandler: " + err.Error())
	}
}

func ExecuteTemplate(tpl *template.Template, w http.ResponseWriter, name string, data any) error {
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