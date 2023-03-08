package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// H is a shorthand for map[string]any
type H map[string]any

// writeJSON writes JSON data to the response body.
// return the error by Encoder.Encode if it fails.
func writeJSON(w http.ResponseWriter, code int, header http.Header, data interface{}) error {
	w.Header().Set("Content-Type", "application/json")
	for k, v := range header {
		w.Header()[k] = v
	}
	w.WriteHeader(code)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		return err
	}

	return nil
}

// readJSON reads JSON data from the response body
func readJSON(r *http.Request, data interface{}) error {
	if err := json.NewDecoder(r.Body).Decode(data); err != nil {
		var syntaxError *json.SyntaxError
		var unmarshalTypeError *json.UnmarshalTypeError
		var invalidUnmarshalError *json.InvalidUnmarshalError

		switch {
		case errors.As(err, &unmarshalTypeError):
			if unmarshalTypeError.Field != "" {
				return fmt.Errorf("json contains an incorrect JSON type for field %s", unmarshalTypeError.Field)
			}
			return fmt.Errorf("json contains an incorrect JSON type (at character %d)", unmarshalTypeError.Offset)
		case errors.As(err, &syntaxError) || errors.Is(err, io.ErrUnexpectedEOF):
			return fmt.Errorf("body contains badly formatted JSON (at character %v)", syntaxError.Offset)
		case errors.Is(err, io.EOF):
			return errors.New("body should not be empty")
		case errors.As(err, &invalidUnmarshalError):
			panic(err)
		case err != nil:
			return err
		}
	}

	return nil
}

// dbConnect creates creates a database pool and immmediately test the connection.
func dbConnect(driverName string, dataSourceURL *url.URL) (*sql.DB, error) {
	db, err := sql.Open("postgres", dataSourceURL.String())
	if err != nil {
		return nil, fmt.Errorf("unable to initialize database %s: %w", dataSourceURL.Redacted(), err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	err = db.PingContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to connect to %s: %w", dataSourceURL.Redacted(), err)
	}

	return db, nil
}
