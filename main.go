package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jastenn/amponin/internal/pkg/oidc/google"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/urfave/cli/v2"
	"github.com/urfave/cli/v2/altsrc"
	_ "go.uber.org/automaxprocs"
	"go.uber.org/zap"
)

const (
	version = "0.1"

	environmentProduction  = "production"
	environmentDevelopment = "development"

	configFileFlagKey      = "config-file"
	portFlagKey            = "port"
	envFlagKey             = "env"
	databaseURLFlagKey     = "database_url"
	readTimeoutFlagKey     = "read-timeout"
	writeTimeoutFlagKey    = "write-timeout"
	idleTimeoutFlagKey     = "idle-timeout"
	shutdownTimeoutFlagKey = "shutdown-timeout"
)

var flags = []cli.Flag{
	&cli.StringFlag{
		Name:  configFileFlagKey,
		Usage: "a YAML configuration file to be used on setting flag values",
		Value: "amponin-server-config.yaml",
	},
	altsrc.NewIntFlag(&cli.IntFlag{
		Name:    portFlagKey,
		Aliases: []string{"p"},
		Usage:   "port to use on running this application",
		EnvVars: []string{"PORT"},
		Value:   8080,
		Action: func(ctx *cli.Context, v int) error {
			if v >= 65536 || v <= 0 {
				return fmt.Errorf("port value %v out of range[0-65535]", v)
			}
			return nil
		},
	}),
	altsrc.NewStringFlag(&cli.StringFlag{
		Name:    envFlagKey,
		Usage:   "current environment that this application will run on",
		Value:   environmentProduction,
		EnvVars: []string{"ENV"},
		Action: func(ctx *cli.Context, s string) error {
			if s != environmentProduction && s != environmentDevelopment {
				return fmt.Errorf("environment %v is invalid, it can only be development or production", s)
			}
			return nil
		},
	}),
	altsrc.NewDurationFlag(&cli.DurationFlag{
		Name:    readTimeoutFlagKey,
		Usage:   "timout to use when reading requests",
		EnvVars: []string{"READ_TIMEOUT"},
		Value:   time.Second * 1,
	}),
	altsrc.NewDurationFlag(&cli.DurationFlag{
		Name:    idleTimeoutFlagKey,
		Usage:   "timout to use on idle requests",
		EnvVars: []string{"IDLE_TIMEOUT"},
		Value:   time.Second * 10,
	}),
	altsrc.NewDurationFlag(&cli.DurationFlag{
		Name:    writeTimeoutFlagKey,
		Usage:   "timout to use on idle requests",
		EnvVars: []string{"WRITE_TIMEOUT"},
		Value:   time.Second * 2,
	}),
	altsrc.NewDurationFlag(&cli.DurationFlag{
		Name:    shutdownTimeoutFlagKey,
		Usage:   "timout to use on idle requests",
		EnvVars: []string{"SHUTDOWN_TIMEOUT"},
		Value:   time.Second * 15,
	}),
	altsrc.NewStringFlag(&cli.StringFlag{
		Name:     databaseURLFlagKey,
		Required: true,
		Action: func(ctx *cli.Context, s string) error {
			_, err := url.Parse(s)
			if err != nil {
				return errors.New("invalid database url")
			}
			return nil
		},
	}),
}

func main() {
	app := &cli.App{
		Name:    "Amponin Server",
		Usage:   "A RESTful api endpoint for handing user request on Amponin",
		Version: version,
		Before: altsrc.InitInputSourceWithContext(
			flags,
			altsrc.NewYamlSourceFromFlagFunc("config-file"),
		),
		Flags: flags,
		Action: func(cCtx *cli.Context) error {
			zapLogger, err := zap.NewProduction()
            log := zapLogger.Sugar() 
			if err != nil {
                err = fmt.Errorf("unable to initialize logger: %w", err)
                log.Error(err)
				return cli.Exit(err, 1)
			}

            databaseURL := cCtx.String(databaseURLFlagKey)
			db, err := sqlx.Connect("postgres", databaseURL)
            if err != nil {
                err = fmt.Errorf("unable to connect to %s: %w", databaseURL, err)
                log.Error(err)
                return cli.Exit(err, 1)
            }

			app := &application{
				log:                   log,
				db:                    db,
				googleIDTokenVerifier: google.NewIDTokenVerifier(""),
				config: applicationConfig{
					port:            cCtx.Int(portFlagKey),
					environment:     cCtx.String(envFlagKey),
					readTimeout:     cCtx.Duration(readTimeoutFlagKey),
					writeTimeout:    cCtx.Duration(writeTimeoutFlagKey),
					idleTimeout:     cCtx.Duration(idleTimeoutFlagKey),
					shutdownTimeout: cCtx.Duration(shutdownTimeoutFlagKey),
				},
			}

			if err := app.run(); err != nil {
				return cli.Exit(err, 1)
			}

			return nil
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		panic(err)
	}
}

type application struct {
	log                   *zap.SugaredLogger
	db                    *sqlx.DB
	googleIDTokenVerifier *google.IDTokenVerifier
	config                applicationConfig
}

type applicationConfig struct {
	port            int
	environment     string
	readTimeout     time.Duration
	writeTimeout    time.Duration
	idleTimeout     time.Duration
	shutdownTimeout time.Duration
}

// run starts up the application.
func (a *application) run() error {
	srv := http.Server{
		Addr:         fmt.Sprintf(":%v", a.config.port),
		Handler:      a.router(),
		ReadTimeout:  a.config.readTimeout,
		WriteTimeout: a.config.writeTimeout,
		IdleTimeout:  a.config.idleTimeout,
	}

	srvErrCh := make(chan error)
	shutdownCh := make(chan os.Signal, 1)

	go func() {
		a.log.Infow(
			"server running",
			"port", srv.Addr,
			"environment", a.config.environment,
		)
		srvErrCh <- srv.ListenAndServe()
	}()

	defer a.log.Infow(
		"server stopped",
	)

	signal.Notify(shutdownCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-srvErrCh:
		return err

	case sig := <-shutdownCh:
		a.log.Infow(
			"shutdown signal recieved",
			"signal", sig,
		)
		a.log.Info("shutting down the server gracefully...")

		ctx, cancel := context.WithTimeout(context.Background(), a.config.shutdownTimeout)
		defer cancel()

		if err := srv.Shutdown(ctx); err != nil {
			a.log.Errorf("unable to shutdown the server gracefully: %w", err)
			a.log.Info("closing all active connection instead")
			srv.Close()

			return err
		}

		return nil
	}
}
