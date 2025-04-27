package main

import (
	"database/sql"
	"flag"
	"log/slog"
	"net/http"
	"os"

	_ "github.com/lib/pq"
)

func main() {
	address := flag.String("address", ":8080", "network address to run on")
	database := flag.String("database", "", "database url to store application data.")
	smtpEmail := flag.String("smtp-email", "", "email address to be used in sending email")
	smtpPassword := flag.String("smtp-password", "", "password to be used in smtp email address authentication")
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
	})
	http.Handle("/signup/verification", &SignupVerificationHandler{
		Log:                 log,
		SessionStore:        sessionStore,
		LocalAccountCreator: store,
		SignupURL:           "/signup",
	})

	log.Info("Server running.", "address", *address)
	http.ListenAndServe(*address, nil)
}
