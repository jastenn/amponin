package main

import (
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
)

type PetResult struct {
	ID          string
	Images      []string
	Name        string
	Distance    float64
	Address     string
	Description string
}

type PetSearchQuery struct {
	Location *Coordinates
	Type     PetType
}

type IndexTemplateData struct {
	LoginSession *LoginSession
	Flash        *Flash
	Query        PetSearchQuery
	Result       []PetResult
}

type IndexHandler struct {
	Log             *slog.Logger
	NotFoundHandler http.Handler
	TemplateFS      fs.FS
	SessionStore    *CookieStore

	indexTemplateCache *template.Template
}

func (i *IndexHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	flash, _ := i.SessionStore.Flash(w, r)
	loginSession, _ := GetLoginSession(i.SessionStore, w, r)
	if r.URL.Path != "" && r.URL.Path != "/" {
		i.NotFoundHandler.ServeHTTP(w, r)
		return
	}

	petType := r.FormValue("type")
	rawCoordinates := r.FormValue("location")
	coordinates, err := ParseCoordinates(rawCoordinates)
	if err != nil {
		i.Log.Debug("Coordinates is invaild.", "coordinates", rawCoordinates)
	}

	if i.indexTemplateCache == nil {
		var err error
		i.indexTemplateCache, err = template.ParseFS(i.TemplateFS, "base.html", "index.html")
		if err != nil {
			panic("unable to parse index template: " + err.Error())
		}
	}
	err = ExecuteTemplate(i.indexTemplateCache, w, "base.html", IndexTemplateData{
		LoginSession: loginSession,
		Flash:        flash,
		Query: PetSearchQuery{
			Location: coordinates,
			Type:     PetType(petType),
		},
	})
	if err != nil {
		panic("unable to execute index template: " + err.Error())
	}
}

type Coordinates struct {
	Longitude float64
	Latitude  float64
}

func ParseCoordinates(s string) (*Coordinates, error) {
	xs := strings.Split(s, ",")
	if len(xs) != 2 {
		return nil, errors.New("invalid coordinates")
	}

	lat, err := strconv.ParseFloat(xs[0], 64)
	if err != nil {
		return nil, fmt.Errorf("invalid coordinates: latitude is invalid: %w", err)
	}
	if lat > 90 || lat < -90 {
		return nil, fmt.Errorf("invalid coordinates: latitude out of bounds")
	}

	lng, err := strconv.ParseFloat(xs[1], 64)
	if err != nil {
		return nil, fmt.Errorf("invalid coordinates: longitude is invalid float: %w", err)
	}
	if lng > 180 || lng < -180 {
		return nil, fmt.Errorf("invalid coordinates: latitude out of bounds")
	}

	return &Coordinates{
		Latitude:  lat,
		Longitude: lng,
	}, nil
}
