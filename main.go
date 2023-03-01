package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/urfave/cli/v2"
	"github.com/urfave/cli/v2/altsrc"
)

const (
	version = "0.1"

	environmentProduction  = "production"
	environmentDevelopment = "development"

	configFileFlagKey      = "config-file"
	portFlagKey            = "port"
	envFlagKey             = "env"
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
		Flags:  flags,
		Action: start,
	}

	err := app.Run(os.Args)
	if err != nil {
		panic(err)
	}
}

func start(cCtx *cli.Context) error {
	srv := http.Server{
		Addr:         fmt.Sprintf(":%v", cCtx.Int(portFlagKey)),
		Handler:      nil,
		ReadTimeout:  cCtx.Duration(readTimeoutFlagKey),
		WriteTimeout: cCtx.Duration(writeTimeoutFlagKey),
		IdleTimeout:  cCtx.Duration(idleTimeoutFlagKey),
	}

	srvErrCh := make(chan error)
	shutdownCh := make(chan os.Signal, 1)

	go func() {
		srvErrCh <- srv.ListenAndServe()
	}()

	signal.Notify(shutdownCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-srvErrCh:
		return err

	case <-shutdownCh:
		ctx, cancel := context.WithTimeout(context.Background(), cCtx.Duration(shutdownTimeoutFlagKey))
		defer cancel()

		if err := srv.Shutdown(ctx); err != nil {
			srv.Close()

			return err
		}
		return nil
	}
}
