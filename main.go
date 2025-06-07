package main

import (
	"database/sql"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"time"

	_ "github.com/lib/pq"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const environmentProduction = "production"
const environmentDevelopment = "development"

const imageStoreBasePath = "image-store"

func main() {
	const loginSessionMaxAge = time.Hour * 24

	address := flag.String("address", ":8080", "network address to run on")
	environment := flag.String("environment", "production", "current environment that this application will run on. (values: development or production)")
	database := flag.String("database", "", "database url to store application data.")
	smtpEmail := flag.String("smtp-email", "", "email address to be used in sending email")
	smtpPassword := flag.String("smtp-password", "", "password to be used in smtp email address authentication")
	googleAuthClientID := flag.String("google-auth-client-id", "", "google client id for google authentication service.")
	googleAuthClientSecret := flag.String("google-auth-client-secret", "", "client secret for google authentication service.")
	googleAuthRedirectURL := flag.String("google-auth-redirect-url", "", "registered url google oauth2 redirect.")
	flag.Parse()

	if *database == "" {
		panic("database is required")
	}
	if *smtpEmail == "" {
		panic("smtp-email is required")
	}
	if *smtpPassword == "" {
		panic("smtp-password is required")
	}
	if *googleAuthClientID == "" {
		panic("google-auth-client-id is required")
	}
	if *googleAuthClientSecret == "" {
		panic("google-auth-client-secret is required")
	}
	if *googleAuthRedirectURL == "" {
		panic("google-auth-redirect-url is required")
	}

	databaseConnection, err := sql.Open("postgres", *database)
	if err != nil {
		panic("unable to open database connection: " + err.Error())
	}

	logOptions := slog.HandlerOptions{}
	if *environment == environmentDevelopment {
		logOptions.Level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stdout, &logOptions))
	sessionStore := NewCookieSessionStore("sikret", CookieSessionStoreOptions{
		Path: "/",
	})
	store := &PGStore{
		DB: databaseConnection,
	}
	imageStore := NewLocalImageStore(imageStoreBasePath)
	mailSender := NewGoogleMailSender(*smtpEmail, *smtpPassword)
	googleOAuth2Config := &oauth2.Config{
		ClientID:     *googleAuthClientID,
		ClientSecret: *googleAuthClientSecret,
		Endpoint:     google.Endpoint,
		RedirectURL:  *googleAuthRedirectURL,
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
	}

	notFoundHandler := &NotFoundHandler{
		SessionStore: sessionStore,
	}

	mux := http.NewServeMux()

	// embedFS contains a static directory which hosts all the static files
	// needed to be served.
	mux.Handle("GET /image-store/", http.StripPrefix("/image-store/", http.FileServer(http.Dir("image-store"))))
	mux.Handle("GET /static/", http.FileServerFS(embedFS))
	mux.Handle("/", &IndexHandler{
		Log:             log,
		SessionStore:    sessionStore,
		NotFoundHandler: notFoundHandler,
	})
	mux.Handle("/signup", &SignupHandler{
		Log:                     log,
		SessionStore:            sessionStore,
		MailSender:              mailSender,
		VerificationRedirectURL: "/signup/verification",
		GoogleOAuth2Config:      googleOAuth2Config,
	})
	mux.Handle("/signup/verification", &SignupVerificationHandler{
		Log:                 log,
		SessionStore:        sessionStore,
		LocalAccountCreator: store,
		SignupURL:           "/signup",
	})
	mux.Handle("/auth/google", &GoogleAuthRedirectHandler{
		Log:                   log,
		GoogleAuthConfig:      googleOAuth2Config,
		SessionStore:          sessionStore,
		ForeignAccountCreator: store,
		ForeignAccountGetter:  store,
		SuccessRedirect:       "/",
		LoginSessionMaxAge:    loginSessionMaxAge,
	})
	mux.Handle("/login", &LoginHandler{
		Log:                log,
		SessionStore:       sessionStore,
		GoogleAuthConfig:   googleOAuth2Config,
		LocalAccountGetter: store,
		LoginSessionMaxAge: loginSessionMaxAge,
		SuccessRedirect:    "/",
	})
	mux.Handle("/logout", &LogoutHandler{
		Log:             log,
		SessionStore:    sessionStore,
		SuccessRedirect: "/",
	})
	mux.Handle("/account", &AccountHandler{
		Log:                log,
		SessionStore:       sessionStore,
		LocalAccountGetter: store,
	})
	mux.Handle("/account/update-info", &AccountInfoUpdateHandler{
		Log:                log,
		SessionStore:       sessionStore,
		ImageStore:         imageStore,
		UserUpdater:        store,
		SuccessRedirectURL: "/account",
	})
	mux.Handle("/account/change-email/request", &AccountChangeEmailRequestHandler{
		Log:                log,
		SessionStore:       sessionStore,
		MailSender:         mailSender,
		SuccessRedirectURL: "/account/change-email",
		ErrorRedirectURL:   "/account",
	})
	mux.Handle("/account/change-email", &AccountEmailChangeHandler{
		Log:                     log,
		SessionStore:            sessionStore,
		MailSender:              mailSender,
		VerificationRedirectURL: "/account/change-email/verification",
		ErrorRedirectURL:        "/account",
	})
	mux.Handle("/account/change-email/verification", &AccountChangeEmailVerificationHandler{
		Log:                log,
		SessionStore:       sessionStore,
		UserUpdateData:     store,
		SuccessRedirectURL: "/account",
		ErrorRedirectURL:   "/account",
	})
	mux.Handle("/account/change-password", &AccountChangePasswordHandler{
		Log:               log,
		SessionStore:      sessionStore,
		LocalAccountStore: store,
		SuccessRedirect:   "/account",
	})
	mux.Handle("/shelter", &ListManagedShelterHandler{
		Log:                  log,
		SessionStore:         sessionStore,
		ManagedShelterFinder: store,
	})
	mux.Handle("/shelter/register", &RegisterShelterHandler{
		Log:                log,
		SessionStore:       sessionStore,
		ShelterRegistry:    store,
		SuccessRedirectURL: "/shelter/{shelter_id}",
	})
	mux.Handle("/shelter/{shelter_id}", &GetShelterByIDHandler{
		Log:               log,
		SessionStore:      sessionStore,
		ShelterGetterByID: store,
		ShelterRoleGetter: store,
		NotFoundHandler:   notFoundHandler,
	})
	mux.Handle("/shelter/{shelter_id}/post", &PostPetHandler{
		Log:               log,
		SessionStore:      sessionStore,
		ShelterRoleGetter: store,
		PetRegistry:       store,
		ImageStore:        imageStore,
	})
	mux.Handle("/pet/{pet_id}", &PetByIDHandler{
		Log:             log,
		SessionStore:    sessionStore,
		PetGetter:       store,
		NotFoundHandler: notFoundHandler,
	})
	mux.Handle("/pets", &FindPetHandler{
		Log:          log,
		SessionStore: sessionStore,
		PetFinder:    store,
	})

	log.Info("Server running.", "address", *address)
	err = http.ListenAndServe(*address, mux)
	if err != nil {
		log.Error("Unable to start server.", "error", err.Error())
	}
}

type RecovererMiddlewareConfig struct {
	Log          *slog.Logger
	SessionStore *CookieSessionStore
}

func ApplyRecovererMiddleware(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			err := recover()
			if err != nil {
				log.Error("Unexpected error occurred.", "error", err)
				renderErrorPage(w, errorPageData{
					Status:  http.StatusInternalServerError,
					Message: clientMessageUnexpectedError,
				})
				return
			}
		}()

		next.ServeHTTP(w, r)
	})
}
