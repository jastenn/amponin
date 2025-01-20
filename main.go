package main

import (
	"context"
	"database/sql"
	"embed"
	"flag"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"time"

	_ "github.com/lib/pq"
)

//go:embed templates/*
//go:embed public/*
//go:embed public/scripts/* public/scripts/components/*
var embedFS embed.FS

func main() {
	address := flag.String("address", ":8080", "network address to bind on")
	writeTimeout := flag.Duration("write-timeout", time.Second*5, "timeout to use when writing response")
	readTimeout := flag.Duration("read-timeout", time.Second*3, "timeout to use when reading request")
	idleTimeout := flag.Duration("idle-timeout", time.Second*8, "timeout to use for idle connection")
	shutdownTimeout := flag.Duration("shutdown-timeout", time.Second*15, "timeout to use waiting for active connections before closing")
	certFile := flag.String("cert-file", "", "path to SSL Certificate to use for secure connection")
	keyFile := flag.String("key-file", "", "path to SSL Key to use for secure connection")
	secret := flag.String("secret", "", "key to be used in encrypting sensitive data")
	smtpEmail := flag.String("smtp-email", "", "email address to be used in sending email")
	smtpPassword := flag.String("smtp-password", "", "password for email address in smtp authentication")
	database := flag.String("database", "", "url to database to be used in storing data")
	baseFileStoreDir := flag.String("base-file-store-dir", "file-store", "Base directory to be used as storage for local store")
	flag.Parse()

	if *certFile == "" {
		panic("cert-file flag required.")
	}
	if *keyFile == "" {
		panic("key-file flag required.")
	}
	if *secret == "" {
		panic("secret flag is required.")
	}
	if *smtpEmail == "" {
		panic("smtp-email flag is required.")
	}
	if *smtpPassword == "" {
		panic("smtp-password flag is required.")
	}
	if *database == "" {
		panic("database flag is required.")
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

	databaseConnection, err := sql.Open("postgres", *database)
	if err != nil {
		panic("unable to open database connection: " + err.Error())
	}
	if err = databaseConnection.Ping(); err != nil {
		panic("failed to ping database: " + err.Error())
	}

	store := &PGStore{
		db: databaseConnection,
	}
	cookieStore := NewCookieStore(*secret)
	emailVerifier := NewGoogleMailSender(*smtpEmail, *smtpPassword)

	handler := http.NewServeMux()
	handler.Handle("GET /public/{filename...}", http.StripPrefix("/public", http.FileServerFS(publicFS)))
	handler.Handle("GET /", &IndexHandler{
		Log:             log,
		TemplateFS:      templatesFS,
		SessionStore:    cookieStore,
		NotFoundHandler: http.NotFoundHandler(),
	})
	handler.Handle("GET /signup", &SignupHandler{
		Log:                 log,
		TemplateFS:          templatesFS,
		SessionStore:        cookieStore,
		LoggedInRedirectURL: "/",
	})
	handler.Handle("POST /signup", &DoSignupHandler{
		Log:                     log,
		TemplateFS:              templatesFS,
		SessionStore:            cookieStore,
		MailSender:              emailVerifier,
		VerificationRedirectURL: "/signup/completion",
	})
	handler.Handle("GET /signup/completion", &SignupCompletionHandler{
		Log:               log,
		TemplateFS:        templatesFS,
		SessionStore:      cookieStore,
		SignupRedirectURL: "/signup",
	})
	handler.Handle("POST /signup/completion", &DoSignupCompletionHandler{
		Log:                 log,
		TemplateFS:          templatesFS,
		SessionStore:        cookieStore,
		SucccessRedirectURL: "/login",
		SignupRedirectURL:   "/signup",
		LocalAccountCreator: store,
	})
	handler.Handle("GET /login", &LoginHandler{
		Log:                log,
		TemplateFS:         templatesFS,
		SessionStore:       cookieStore,
		SuccessRedirectURL: "/",
	})
	handler.Handle("POST /login", &DoLoginHandler{
		Log:                log,
		TemplateFS:         templatesFS,
		SessionStore:       cookieStore,
		SuccessRedirectURL: "/",
		LoginSessionMaxAge: time.Hour * 24 * 7,
		LocalAccountGetter: store,
	})
	handler.Handle("POST /logout", &DoLogout{
		Log:          log,
		SessionStore: cookieStore,
	})
	handler.Handle("GET /shelter", &ShelterHandler{
		Log:                log,
		TemplateFS:         templatesFS,
		SessionStore:       cookieStore,
		UserSheltersFinder: store,
	})
	handler.Handle("GET /shelter/registration", &ShelterRegistrationHandler{
		TemplateFS:              templatesFS,
		SessionStore:            cookieStore,
		UnauthorizedRedirectURL: "/login?callback=%2Fshelter%2Fregistration",
	})
	handler.Handle("GET /shelter/{id}", &ShelterByIDHandler{
		Log:                log,
		TemplateFS:         templatesFS,
		SessionStore:       cookieStore,
		NotFoundHandler:    http.NotFoundHandler(),
		ShelterGetter:      store,
		ShelterRoleGetterr: store,
	})
	handler.Handle("POST /shelter/registration", &DoShelterRegistrationHandler{
		TemplateFS:              templatesFS,
		Log:                     log,
		SessionStore:            cookieStore,
		UnauthorizedRedirectURL: "/login?callback=%2Fshelter%2Fregistration",
		ShelterCreator:          store,
		SuccessRedirect:         "/",
	})
	handler.Handle("GET /shelter/{id}/post-pet", &PostPetHandler{
		TemplateFS:   templatesFS,
		SessionStore: cookieStore,
	})
	handler.Handle("POST /shelter/{id}/post-pet", &DoPetPostHandler{
		TemplateFS:   templatesFS,
		Log:          log,
		SessionStore: cookieStore,
		FileStore: &LocalFileStore{
			BaseDir: *baseFileStoreDir,
		},
		PetRegistry: store,
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
