package main

import (
	"database/sql"
	"flag"
	"log/slog"
	"net/http"
	"os"

	_ "github.com/lib/pq"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

func main() {
	address := flag.String("address", ":8080", "network address to run on")
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

	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	sessionStore := NewCookieSessionStore("sikret", CookieSessionStoreOptions{
		Path: "/",
	})
	store := &PGStore{
		DB: databaseConnection,
	}
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

	// embedFS contains a static directory which hosts all the static files
	// needed to be served.
	http.Handle("GET /static/", http.FileServerFS(embedFS))
	http.Handle("/", &IndexHandler{
		Log:             log,
		NotFoundHandler: &NotFoundHandler{},
	})
	http.Handle("/signup", &SignupHandler{
		Log:                     log,
		SessionStore:            sessionStore,
		MailSender:              mailSender,
		VerificationRedirectURL: "/signup/verification",
		GoogleOAuth2Config:      googleOAuth2Config,
	})
	http.Handle("/signup/verification", &SignupVerificationHandler{
		Log:                 log,
		SessionStore:        sessionStore,
		LocalAccountCreator: store,
		SignupURL:           "/signup",
	})
	http.Handle("/auth/google", &GoogleAuthRedirectHandler{
		Log:                   log,
		GoogleOAuth2Config:    googleOAuth2Config,
		SessionStore:          sessionStore,
		ForeignAccountCreator: store,
		SignupURL:             "/signup",
	})

	log.Info("Server running.", "address", *address)
	err = http.ListenAndServe(*address, nil)
	if err != nil {
		log.Error("Unable to start server.", err.Error())
	}
}
