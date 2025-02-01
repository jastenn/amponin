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

	scs "github.com/alexedwards/scs/v2"
	_ "github.com/lib/pq"
)

//go:embed templates/*
//go:embed public/*
//go:embed public/styles/* public/styles/components/* public/styles/pages/*
//go:embed public/scripts/* public/scripts/components/* public/scripts/pages/*
var embedFS embed.FS

func main() {
	address := flag.String("address", ":8080", "network address to bind on")
	writeTimeout := flag.Duration("write-timeout", time.Second*5, "timeout to use when writing response")
	readTimeout := flag.Duration("read-timeout", time.Second*3, "timeout to use when reading request")
	idleTimeout := flag.Duration("idle-timeout", time.Second*8, "timeout to use for idle connection")
	shutdownTimeout := flag.Duration("shutdown-timeout", time.Second*15, "timeout to use waiting for active connections before closing")
	certFile := flag.String("cert-file", "", "path to SSL Certificate to use for secure connection")
	keyFile := flag.String("key-file", "", "path to SSL Key to use for secure connection")
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
	if *smtpEmail == "" {
		panic("smtp-email flag is required.")
	}
	if *smtpPassword == "" {
		panic("smtp-password flag is required.")
	}
	if *database == "" {
		panic("database flag is required.")
	}

	fileStore := &LocalFileStore{
		BaseDir: *baseFileStoreDir,
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

	postgresStore := &PGStore{
		db: databaseConnection,
	}

	sessionManager := scs.New()

	emailVerifier := NewGoogleMailSender(*smtpEmail, *smtpPassword)

	handler := http.NewServeMux()
	handler.Handle("GET /public/{filename...}",
		http.StripPrefix("/public", http.FileServerFS(publicFS)),
	)
	handler.Handle("GET /file-store/{filename...}",
		http.StripPrefix(
			"/file-store",
			NewSafeFileServer(http.Dir("file-store")),
		),
	)
	handler.Handle("GET /", &IndexHandler{
		SessionManager: sessionManager,
		TemplateFS:     templatesFS,
	})
	handler.Handle("GET /signup", &SignupHandler{
		Log:                 log,
		TemplateFS:          templatesFS,
		SessionManager:      sessionManager,
		LoggedInRedirectURL: "/",
	})
	handler.Handle("POST /signup", &DoSignupHandler{
		Log:                     log,
		TemplateFS:              templatesFS,
		SessionManager:          sessionManager,
		MailSender:              emailVerifier,
		VerificationRedirectURL: "/signup/completion",
	})
	handler.Handle("GET /signup/completion", &SignupCompletionHandler{
		Log:               log,
		TemplateFS:        templatesFS,
		SessionManager:    sessionManager,
		SignupRedirectURL: "/signup",
	})
	handler.Handle("POST /signup/completion", &DoSignupCompletionHandler{
		Log:                 log,
		TemplateFS:          templatesFS,
		SessionManager:      sessionManager,
		SucccessRedirectURL: "/login",
		SignupRedirectURL:   "/signup",
		LocalAccountCreator: postgresStore,
	})
	handler.Handle("GET /login", &LoginHandler{
		Log:                log,
		TemplateFS:         templatesFS,
		SessionManager:     sessionManager,
		SuccessRedirectURL: "/",
	})
	handler.Handle("POST /login", &DoLoginHandler{
		Log:                log,
		TemplateFS:         templatesFS,
		SessionManager:     sessionManager,
		SuccessRedirectURL: "/",
		LoginSessionMaxAge: time.Hour * 24 * 7,
		LocalAccountGetter: postgresStore,
	})
	handler.Handle("POST /logout", &DoLogout{
		Log:            log,
		SessionManager: sessionManager,
	})
	handler.Handle("GET /pets", &PetsHandler{
		Log:                 log,
		SessionManager:      sessionManager,
		TemplateFS:          templatesFS,
		PetFinderByLocation: postgresStore,
	})
	handler.Handle("GET /account-settings", &AccountSettingsHandler{
		Log:              log,
		TemplateFS:       templatesFS,
		SessionManager:   sessionManager,
		UserGetterByID:   postgresStore,
		LoginRedirectURL: "/login?callback=%2Faccount-settings",
	})
	handler.Handle("POST /account-settings", &DoAccountSettingsHandler{
		TemplateFS:                 templatesFS,
		Log:                        log,
		SessionStore:               sessionManager,
		UserGetterByID:             postgresStore,
		FileStore:                  fileStore,
		UnauthenticatedRedirectURL: "/login?callback=%2Faccount-settings",
		SuccessRedirectURL:         "/account-settings",
		UserInfoUpdater:            postgresStore,
	})
	handler.Handle("GET /shelter", &ShelterHandler{
		Log:                log,
		TemplateFS:         templatesFS,
		SessionManager:     sessionManager,
		UserSheltersFinder: postgresStore,
	})
	handler.Handle("GET /shelter/registration", &ShelterRegistrationHandler{
		TemplateFS:              templatesFS,
		SessionStore:            sessionManager,
		UnauthorizedRedirectURL: "/login?callback=%2Fshelter%2Fregistration",
	})
	handler.Handle("POST /shelter/registration", &DoShelterRegistrationHandler{
		TemplateFS:              templatesFS,
		Log:                     log,
		SessionStore:            sessionManager,
		UnauthorizedRedirectURL: "/login?callback=%2Fshelter%2Fregistration",
		ShelterCreator:          postgresStore,
		SuccessRedirectURL:      "/shelter/{shelter_id}",
	})
	handler.Handle("GET /shelter/{id}", &ShelterByIDHandler{
		Log:               log,
		TemplateFS:        templatesFS,
		SessionManager:    sessionManager,
		NotFoundHandler:   http.NotFoundHandler(),
		ShelterGetter:     postgresStore,
		ShelterRoleGetter: postgresStore,
	})
	handler.Handle("GET /shelter/{id}/post-pet", &PostPetHandler{
		TemplateFS:        templatesFS,
		Log:               log,
		SessionManager:    sessionManager,
		ShelterRoleGetter: postgresStore,
		LoginRedirectURL:  "/login?callback=%2Fshelter%2F{shelter_id}%2Fpost-pet",
	})
	handler.Handle("POST /shelter/{shelter_id}/post-pet", &DoPetPostHandler{
		TemplateFS:         templatesFS,
		Log:                log,
		SessionManager:     sessionManager,
		ShelterRoleGetter:  postgresStore,
		FileStore:          fileStore,
		PetRegistry:        postgresStore,
		SuccessRedirectURL: "/{pet_id}",
	})
	handler.Handle("GET /{pet_id}", &PetByIDHandler{
		Log:             log,
		SessionManager:  sessionManager,
		NotFoundHandler: http.NotFoundHandler(),
		TemplateFS:      templatesFS,
		PetGetter:       postgresStore,
		ShelterGetter:   postgresStore,
	})

	server := http.Server{
		Addr:         *address,
		Handler:      sessionManager.LoadAndSave(handler),
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
