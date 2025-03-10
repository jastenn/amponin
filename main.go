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
	"github.com/justinas/alice"
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
		panic("unable to extract public fs from embedded fs: " + err.Error())
	}

	templatesFS, err := fs.Sub(embedFS, "templates")
	if err != nil {
		panic("unable to extract templates fs from embedded fs: " + err.Error())
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

	pageTemplateRenderer := NewFSPageTemplateRenderer(templatesFS)

	mailTemplateFS, err := fs.Sub(templatesFS, "mail")
	if err != nil {
		panic("unable to extract mail templates from embedded fs: " + err.Error())
	}
	mailTemplateRenderer := NewFSMailTemplateRenderer(mailTemplateFS)

	postgresDataStore := &PGStore{
		db: databaseConnection,
	}

	sessionManager := scs.New()
	sessionManager.Store = postgresstore.New(databaseConnection)

	googleEmailSender := NewGoogleMailSender(*smtpEmail, *smtpPassword)

	authorizedSessionUserMiddleware := &AuthorizedSessionUserMiddleware{
		Log:                     log.WithGroup("AuthorizedSessionUserMiddleware"),
		SessionManager:          sessionManager,
		UnauthorizedMessage:     "Please login first.",
		UnauthorizedRedirectURL: "/login",
		CurrentPathQueryKey:     "callback",
	}

	notfoundHandler := http.NotFoundHandler()

	mux := http.NewServeMux()
	mux.Handle("GET /public/{filename...}",
		http.StripPrefix("/public", http.FileServerFS(publicFS)),
	)
	mux.Handle("GET /file-store/{filename...}",
		http.StripPrefix(
			"/file-store",
			NewSafeFileServer(http.Dir("file-store")),
		),
	)
	mux.Handle("GET /", &IndexHandler{
		SessionManager:       sessionManager,
		PageTemplateRenderer: pageTemplateRenderer,
		NotFoundHandler:      notfoundHandler,
	})
	mux.Handle("GET /signup", &SignupHandler{
		Log:                  log.With("path", "GET /signup"),
		PageTemplateRenderer: pageTemplateRenderer,
		SessionManager:       sessionManager,
		SuccessRedirectURL:   "/",
	})
	mux.Handle("POST /signup", &DoSignupHandler{
		Log:                     log.With("path", "POST /signup"),
		PageTemplateRenderer:    pageTemplateRenderer,
		SessionManager:          sessionManager,
		MailSender:              googleEmailSender,
		VerificationRedirectURL: "/signup/verification",
	})
	mux.Handle("GET /signup/verification", &SignupCompletionHandler{
		Log:                  log.With("path", "GET /signup/verification"),
		PageTemplateRenderer: pageTemplateRenderer,
		SessionManager:       sessionManager,
		SignupRedirectURL:    "/signup",
	})
	mux.Handle("POST /signup/verification", &DoSignupCompletionHandler{
		Log:                  log.With("path", "POST /signup/verification"),
		PageTemplateRenderer: pageTemplateRenderer,
		SessionManager:       sessionManager,
		LocalAccountCreator:  postgresDataStore,
		SignupRedirectURL:    "/signup",
		SucccessRedirectURL:  "/login",
	})
	mux.Handle("GET /login", &LoginHandler{
		Log:                  log.With("path", "GET /login"),
		PageTemplateRenderer: pageTemplateRenderer,
		SessionManager:       sessionManager,
		SuccessRedirectURL:   "/",
	})
	mux.Handle("POST /login", &DoLoginHandler{
		Log:                       log.With("path", "POST /login"),
		PageTemplateRenderer:      pageTemplateRenderer,
		SessionManager:            sessionManager,
		SuccessRedirectURL:        "/",
		LoginSessionMaxAge:        time.Hour * 24 * 7,
		LocalAccountGetterByEmail: postgresDataStore,
	})
	mux.Handle("POST /logout", &DoLogout{
		Log:            log.With("path", "POST /logout"),
		SessionManager: sessionManager,
	})
	mux.Handle("GET /account",
		authorizedSessionUserMiddleware.Apply(&AccountSettingsHandler{
			Log:                  log.With("path", "GET /account"),
			PageTemplateRenderer: pageTemplateRenderer,
			SessionManager:       sessionManager,
			UserGetterByID:       postgresDataStore,
		}),
	)
	mux.Handle("POST /account",
		authorizedSessionUserMiddleware.Apply(&DoAccountHandler{
			PageTemplateRenderer:      pageTemplateRenderer,
			MailRenderer:              mailTemplateRenderer,
			Log:                       log.With("path", "POST /account"),
			SessionManager:            sessionManager,
			UserStore:                 postgresDataStore,
			FileStore:                 fileStore,
			MailSender:                googleEmailSender,
			EmailUpdateRequestCreator: postgresDataStore,
			EmailUpdateRequestURL: &url.URL{
				Scheme: "https",
				Host:   *host,
				Path:   "/account/email-update",
			},
			EmailUpdateRequestMaxAge: time.Minute * 5,
			SuccessRedirectURL:       "/account",
			LocalAccountStore:        postgresDataStore,
		}),
	)
	mux.Handle("GET /account/email-update",
		authorizedSessionUserMiddleware.Apply(&AccountEmailUpdateHandler{
			Log:                      log.With("path", "GET /account/email-update"),
			PageTemplateRenderer:     pageTemplateRenderer,
			SessionManager:           sessionManager,
			EmailUpdateRequestGetter: postgresDataStore,
		}),
	)
	mux.Handle("POST /account/email-update",
		authorizedSessionUserMiddleware.Apply(&DoAccountEmailUpdateHandler{
			Log:                       log.With("path", "POST /account/email-update"),
			PageTemplateRenderer:      pageTemplateRenderer,
			SessionManager:            sessionManager,
			EmailUpdateRequestStore:   postgresDataStore,
			LocalAccountGetterByEmail: postgresDataStore,
			MailSender:                googleEmailSender,
			VerificationRedirectURL:   "/account/email-update/verification",
		}),
	)
	mux.Handle("GET /account/email-update/verification", &EmailUpdateVerificationHandler{
		Log:                  log.With("path", "GET /account/email-update/verification"),
		PageTemplateRenderer: pageTemplateRenderer,
		SessionManager:       sessionManager,
	})
	mux.Handle("POST /account/email-update/verification", &DoEmailUpdateVerficationHandler{
		Log:                  log.With("path", "POST /account/email-update/verification"),
		SessionManager:       sessionManager,
		PageTemplateRenderer: pageTemplateRenderer,
		UserInfoUpdater:      postgresDataStore,
	})
	mux.Handle("GET /shelter",
		authorizedSessionUserMiddleware.Apply(&ShelterHandler{
			Log:                  log.With("path", "GET /shelter"),
			PageTemplateRenderer: pageTemplateRenderer,
			SessionManager:       sessionManager,
			UserSheltersFinder:   postgresDataStore,
		}),
	)
	mux.Handle("GET /shelter/registration",
		authorizedSessionUserMiddleware.Apply(&ShelterRegistrationHandler{
			Log:                  log,
			PageTemplateRenderer: pageTemplateRenderer,
			SessionManager:       sessionManager,
		}),
	)
	mux.Handle("POST /shelter/registration",
		authorizedSessionUserMiddleware.Apply(&DoShelterRegistrationHandler{
			PageTemplateRenderer: pageTemplateRenderer,
			Log:                  log.With("path", "POST /shelter/registration"),
			SessionManager:       sessionManager,
			ShelterCreator:       postgresDataStore,
			SuccessRedirectURL:   "/shelter/{shelter_id}",
		}),
	)
	mux.Handle("GET /shelter/{shelter_id}", &ShelterByIDHandler{
		Log:                  log.With("path", "GET /shelter/{shelter_id}"),
		PageTemplateRenderer: pageTemplateRenderer,
		SessionManager:       sessionManager,
		NotFoundHandler:      notfoundHandler,
		ShelterGetter:        postgresDataStore,
		ShelterRoleGetter:    postgresDataStore,
	})
	mux.Handle("GET /shelter/{shelter_id}/post-pet",
		authorizedSessionUserMiddleware.Apply(&PostPetHandler{
			PageTemplateRenderer: pageTemplateRenderer,
			Log:                  log.With("path", "GET /shelter/{shelter_id}/post-pet"),
			SessionManager:       sessionManager,
			ShelterRoleGetter:    postgresDataStore,
		}),
	)
	mux.Handle("POST /shelter/{shelter_id}/post-pet",
		authorizedSessionUserMiddleware.Apply(&DoPetPostHandler{
			Log:                  log.With("path", "POST /shelter/{shelter_id}/post-pet"),
			PageTemplateRenderer: pageTemplateRenderer,
			SessionManager:       sessionManager,
			ShelterRoleGetter:    postgresDataStore,
			FileStore:            fileStore,
			PetRegistry:          postgresDataStore,
			SuccessRedirectURL:   "/{pet_id}",
		}),
	)
	mux.Handle("GET /shelter/{shelter_id}/settings",
		authorizedSessionUserMiddleware.Apply(&ShelterSettingsHandler{
			Log:                  log.With("path", "GET /shelter/{shelter_id}/settings"),
			PageTemplateRenderer: pageTemplateRenderer,
			SessionManager:       sessionManager,
			NotFoundHandler:      notfoundHandler,
			ShelterRoleGetter:    postgresDataStore,
			ShelterGetter:        postgresDataStore,
		}),
	)
	mux.Handle("GET /shelter/{shelter_id}/update",
		authorizedSessionUserMiddleware.Apply(&ShelterUpdateHandler{
			Log:                  log.With("path", "GET /shelter/{shelter_id}/settings"),
			PageTemplateRenderer: pageTemplateRenderer,
			SessionManager:       sessionManager,
			NotFoundHandler:      notfoundHandler,
			ShelterRoleGetter:    postgresDataStore,
			ShelterGetter:        postgresDataStore,
		}),
	)
	mux.Handle("POST /shelter/{shelter_id}/update",
		authorizedSessionUserMiddleware.Apply(&DoShelterUpdateHandler{
			Log:                  log.With("path", "GET /shelter/{shelter_id}/settings"),
			PageTemplateRenderer: pageTemplateRenderer,
			SessionManager:       sessionManager,
			NotFoundHandler:      notfoundHandler,
			ShelterRoleGetter:    postgresDataStore,
			ShelterGetter:        postgresDataStore,
			ShelterUpdater:       postgresDataStore,
			FileStore:            fileStore,
			SuccessRedirectURL:   "/shelter/{shelter_id}",
		}),
	)
	mux.Handle("GET /shelter/{shelter_id}/roles",
		authorizedSessionUserMiddleware.Apply(&ShelterRolesHandler{
			Log:                  log.With("path", "GET /shelter/{shelter_id}/roles"),
			PageTemplateRenderer: pageTemplateRenderer,
			SessionManager:       sessionManager,
			ShelterRolesFinder:   postgresDataStore,
			ShelterGetter:        postgresDataStore,
			ShelterRoleGetter:    postgresDataStore,
			NotFoundHandler:      notfoundHandler,
		}),
	)
	mux.Handle("GET /shelter/{shelter_id}/roles/add",
		authorizedSessionUserMiddleware.Apply(&ShelterAddRoleHandler{
			Log:                  log.With("path", "GET /shelter/{shelter_id}/roles/add"),
			PageTemplateRenderer: pageTemplateRenderer,
			SessionManager:       sessionManager,
			ShelterGetter:        postgresDataStore,
			ShelterRoleGetter:    postgresDataStore,
			NotFoundHandler:      notfoundHandler,
		}),
	)
	mux.Handle("POST /shelter/{shelter_id}/roles/add",
		authorizedSessionUserMiddleware.Apply(&DoShelterAddRoleHandler{
			Log:                  log.With("path", "POST /shelter/{shelter_id}/roles/add"),
			PageTemplateRenderer: pageTemplateRenderer,
			SessionManager:       sessionManager,
			ShelterGetter:        postgresDataStore,
			ShelterRoleGetter:    postgresDataStore,
			NotFoundHandler:      notfoundHandler,
			SuccessRedirect:      "/shelter/{shelter_id}/roles",
			ShelterRoleCreator:   postgresDataStore,
		}),
	)
	mux.Handle("GET /shelter/{shelter_id}/roles/remove",
		authorizedSessionUserMiddleware.Apply(&ShelterRemoveRoleHandler{
			Log:                  log.With("path", "GET /shelter/{shelter_id}/roles/remove"),
			PageTemplateRenderer: pageTemplateRenderer,
			SessionManager:       sessionManager,
			ShelterGetter:        postgresDataStore,
			ShelterRoleGetter:    postgresDataStore,
			NotFoundHandler:      notfoundHandler,
		}),
	)
	mux.Handle("POST /shelter/{shelter_id}/roles/remove",
		authorizedSessionUserMiddleware.Apply(&DoShelterRemoveRoleHandler{
			Log:                  log.With("path", "POST /shelter/{shelter_id}/roles/remove"),
			PageTemplateRenderer: pageTemplateRenderer,
			SessionManager:       sessionManager,
			ShelterGetter:        postgresDataStore,
			ShelterRoleStore:     postgresDataStore,
			NotFoundHandler:      notfoundHandler,
			SuccessRedirect:      "/shelter/{shelter_id}/roles",
			ShelterRoleDeleter:   postgresDataStore,
		}),
	)
	mux.Handle("GET /shelter/{shelter_id}/roles/edit",
		authorizedSessionUserMiddleware.Apply(&ShelterEditRoleHandler{
			Log:                  log.With("path", "GET /shelter/{shelter_id}/roles/edit"),
			PageTemplateRenderer: pageTemplateRenderer,
			SessionManager:       sessionManager,
			ShelterRoleStore:     postgresDataStore,
			ShelterGetter:        postgresDataStore,
			NotFoundHandler:      notfoundHandler,
		}),
	)
	mux.Handle("POST /shelter/{shelter_id}/roles/edit",
		authorizedSessionUserMiddleware.Apply(&DoShelterEditRoleHandler{
			Log:                  log.With("path", "POST /shelter/{shelter_id}/roles/edit"),
			PageTemplateRenderer: pageTemplateRenderer,
			SessionManager:       sessionManager,
			ShelterRoleStore:     postgresDataStore,
			ShelterGetter:        postgresDataStore,
			NotFoundHandler:      notfoundHandler,
			SuccessRedirectURL:   "/shelter/{shelter_id}/roles",
		}),
	)
	mux.Handle("GET /pets", &PetsHandler{
		Log:                  log.With("path", "GET /pets"),
		SessionManager:       sessionManager,
		PageTemplateRenderer: pageTemplateRenderer,
		PetFinderByLocation:  postgresDataStore,
	})
	mux.Handle("GET /{pet_id}", &PetByIDHandler{
		Log:                  log.With("path", "GET /{pet_id}"),
		PageTemplateRenderer: pageTemplateRenderer,
		SessionManager:       sessionManager,
		NotFoundHandler:      notfoundHandler,
		PetGetter:            postgresDataStore,
		ShelterGetter:        postgresDataStore,
	})

	app := alice.New(
		sessionManager.LoadAndSave,
		NewSessionUserMiddleware(sessionManager),
	).Then(mux)

	server := http.Server{
		Addr:         *address,
		Handler:      app,
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
