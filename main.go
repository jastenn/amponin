package main

import (
	"context"
	"database/sql"
	"embed"
	"flag"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"time"

	"github.com/alexedwards/scs/postgresstore"
	"github.com/alexedwards/scs/v2"
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
	host := flag.String("host", "", "host or hostname:port where this application is hosted on")
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
	if *host == "" {
		panic("host flag is required.")
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

	pageRenderer := NewFSPageRenderer(templatesFS)

	postgresDataStore := &PGStore{
		db: databaseConnection,
	}

	sessionManager := scs.New()
	sessionManager.Store = postgresstore.New(databaseConnection)

	googleEmailSender := NewGoogleMailSender(*smtpEmail, *smtpPassword)

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
		SessionManager:  sessionManager,
		TemplateFS:      templatesFS,
		NotFoundHandler: http.NotFoundHandler(),
	})
	handler.Handle("GET /signup", &SignupHandler{
		Log:                 log.With("path", "GET /signup"),
		TemplateFS:          templatesFS,
		SessionManager:      sessionManager,
		LoggedInRedirectURL: "/",
	})
	handler.Handle("POST /signup", &DoSignupHandler{
		Log:                     log.With("path", "POST /signup"),
		TemplateFS:              templatesFS,
		SessionManager:          sessionManager,
		MailSender:              googleEmailSender,
		VerificationRedirectURL: "/signup/completion",
	})
	handler.Handle("GET /signup/completion", &SignupCompletionHandler{
		Log:               log.With("path", "GET /signup/completion"),
		TemplateFS:        templatesFS,
		SessionManager:    sessionManager,
		SignupRedirectURL: "/signup",
	})
	handler.Handle("POST /signup/completion", &DoSignupCompletionHandler{
		Log:                 log.With("path", "POST /signup/completion"),
		TemplateFS:          templatesFS,
		SessionManager:      sessionManager,
		SucccessRedirectURL: "/login",
		SignupRedirectURL:   "/signup",
		LocalAccountCreator: postgresDataStore,
	})
	handler.Handle("GET /login", &LoginHandler{
		Log:                log.With("path", "GET /login"),
		TemplateFS:         templatesFS,
		SessionManager:     sessionManager,
		SuccessRedirectURL: "/",
	})
	handler.Handle("POST /login", &DoLoginHandler{
		Log:                       log.With("path", "POST /login"),
		TemplateFS:                templatesFS,
		SessionManager:            sessionManager,
		SuccessRedirectURL:        "/",
		LoginSessionMaxAge:        time.Hour * 24 * 7,
		LocalAccountGetterByEmail: postgresDataStore,
	})
	handler.Handle("POST /logout", &DoLogout{
		Log:            log.With("path", "POST /logout"),
		SessionManager: sessionManager,
	})
	handler.Handle("GET /pets", &PetsHandler{
		Log:                 log.With("path", "GET /pets"),
		SessionManager:      sessionManager,
		TemplateFS:          templatesFS,
		PetFinderByLocation: postgresDataStore,
	})
	handler.Handle("GET /account", &AccountSettingsHandler{
		Log:              log.With("path", "GET /account"),
		TemplateFS:       templatesFS,
		SessionManager:   sessionManager,
		UserGetterByID:   postgresDataStore,
		LoginRedirectURL: "/login?callback=%2Faccount",
	})
	handler.Handle("POST /account", &DoAccountHandler{
		TemplateFS:                 templatesFS,
		Log:                        log.With("path", "POST /account"),
		SessionStore:               sessionManager,
		UserStore:                  postgresDataStore,
		FileStore:                  fileStore,
		UnauthenticatedRedirectURL: "/login?callback=%2Faccount",
		MailSender:                 googleEmailSender,
		EmailChangeRequestCreator:  postgresDataStore,
		EmailChangeRequestURL: &url.URL{
			Scheme: "https",
			Host:   *host,
			Path:   "/account/change-email",
		},
		EmailChangeRequestMaxAge: time.Minute * 5,
		SuccessRedirectURL:       "/account",
		LocalAccountStore:        postgresDataStore,
	})
	handler.Handle("GET /account/change-email", &AccountChangeEmailHandler{
		Log:                      log.With("path", "GET /account/change-email"),
		PageRenderer:             pageRenderer,
		SessionManager:           sessionManager,
		EmailChangeRequestGetter: postgresDataStore,
	})
	handler.Handle("POST /account/change-email", &DoAccountChangeEmailHandler{
		Log:                       log.With("path", "POST /account/change-email"),
		PageRenderer:              pageRenderer,
		SessionManager:            sessionManager,
		EmailChangeRequestStore:   postgresDataStore,
		LocalAccountGetterByEmail: postgresDataStore,
		MailSender:                googleEmailSender,
		VerificationRedirectURL:   "/account/change-email/verification",
	})
	handler.Handle("GET /account/change-email/verification", &ChangeEmailVerificationHandler{
		PageRenderer:   pageRenderer,
		SessionManager: sessionManager,
	})
	handler.Handle("POST /account/change-email/verification", &DoChangeEmailVerficationHandler{
		Log:             log.With("path", "POST /account/change-email/verification"),
		SessionManager:  sessionManager,
		PageRenderer:    pageRenderer,
		UserInfoUpdater: postgresDataStore,
	})
	handler.Handle("GET /shelter", &ShelterHandler{
		Log:                log.With("path", "GET /shelter"),
		TemplateFS:         templatesFS,
		SessionManager:     sessionManager,
		UserSheltersFinder: postgresDataStore,
	})
	handler.Handle("GET /shelter/registration", &ShelterRegistrationHandler{
		TemplateFS:              templatesFS,
		SessionStore:            sessionManager,
		UnauthorizedRedirectURL: "/login?callback=%2Fshelter%2Fregistration",
	})
	handler.Handle("POST /shelter/registration", &DoShelterRegistrationHandler{
		TemplateFS:              templatesFS,
		Log:                     log.With("path", "POST /shelter/registration"),
		SessionStore:            sessionManager,
		UnauthorizedRedirectURL: "/login?callback=%2Fshelter%2Fregistration",
		ShelterCreator:          postgresDataStore,
		SuccessRedirectURL:      "/shelter/{shelter_id}",
	})
	handler.Handle("GET /shelter/{id}", &ShelterByIDHandler{
		Log:               log.With("path", "GET /shelter/{id}"),
		TemplateFS:        templatesFS,
		SessionManager:    sessionManager,
		NotFoundHandler:   http.NotFoundHandler(),
		ShelterGetter:     postgresDataStore,
		ShelterRoleGetter: postgresDataStore,
	})
	handler.Handle("GET /shelter/{id}/post-pet", &PostPetHandler{
		TemplateFS:        templatesFS,
		Log:               log.With("path", "GET /shelter/{id}/post-pet"),
		SessionManager:    sessionManager,
		ShelterRoleGetter: postgresDataStore,
		LoginRedirectURL:  "/login?callback=%2Fshelter%2F{shelter_id}%2Fpost-pet",
	})
	handler.Handle("POST /shelter/{shelter_id}/post-pet", &DoPetPostHandler{
		TemplateFS:         templatesFS,
		Log:                log.With("path", "POST /shelter/{shelter_id}/post-pet"),
		SessionManager:     sessionManager,
		ShelterRoleGetter:  postgresDataStore,
		FileStore:          fileStore,
		PetRegistry:        postgresDataStore,
		SuccessRedirectURL: "/{pet_id}",
	})
	handler.Handle("GET /{pet_id}", &PetByIDHandler{
		Log:             log.With("path", "GET /{pet_id}"),
		SessionManager:  sessionManager,
		NotFoundHandler: http.NotFoundHandler(),
		TemplateFS:      templatesFS,
		PetGetter:       postgresDataStore,
		ShelterGetter:   postgresDataStore,
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
