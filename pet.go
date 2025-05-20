package main

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

type PetType string

const (
	PetTypeDog PetType = "dog"
	PetTypeCat PetType = "cat"
)

var ErrNoPet = errors.New("no pet was found")

type Gender string

const (
	GenderMale   Gender = "male"
	GenderFemale Gender = "female"
)

type Pet struct {
	ID                string
	Name              string
	Gender            Gender
	Type              PetType
	BirthDate         time.Time
	IsBirthDateApprox bool
	Images            []Image
	Description       string
	RegisteredAt      time.Time
	UpdatedAt         time.Time
}

type PetByIDHandler struct {
	Log             *slog.Logger
	SessionStore    *CookieSessionStore
	PetGetter       petGetter
	NotFoundHandler http.Handler
}

type petGetter interface {
	GetPetByID(ctx context.Context, id string) (*Pet, *Shelter, error)
}

type petByIDPageData struct {
	basePageData
	Pet     *Pet
	Shelter *Shelter
}

var petByIDPage = template.Must(template.New("pet_by_id").
	Funcs(template.FuncMap{"calculate_age": calculateAge}).
	ParseFS(embedFS, "templates/pages/pet/get_by_id.html", "templates/pages/base.html"))

func (p *PetByIDHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var loginSessionData *loginSession
	p.SessionStore.Decode(r, sessionKeyLoginSession, &loginSessionData)

	petID := r.PathValue("pet_id")

	pet, shelter, err := p.PetGetter.GetPetByID(r.Context(), petID)
	if err != nil {
		if errors.Is(err, ErrNoPet) {
			p.Log.Debug("No pet was found with the given id.", "pet_id", petID)
			p.NotFoundHandler.ServeHTTP(w, r)
			return
		}

		p.Log.Error("Unable to get pet.", "reason", err.Error())
		renderErrorPage(w, errorPageData{
			basePageData: basePageData{
				LoginSession: loginSessionData,
			},
			Status:  http.StatusInternalServerError,
			Message: clientMessageUnexpectedError,
		})
		return
	}

	err = RenderPage(w, petByIDPage, http.StatusOK, petByIDPageData{
		basePageData: basePageData{
			LoginSession: loginSessionData,
		},
		Pet:     pet,
		Shelter: shelter,
	})
	if err != nil {
		p.Log.Error("Unable to render pet by id page.", "reason", err.Error())
		renderErrorPage(w, errorPageData{
			basePageData: basePageData{
				LoginSession: loginSessionData,
			},
			Status:  http.StatusInternalServerError,
			Message: clientMessageUnexpectedError,
		})
	}
}

func calculateAge(t time.Time) string {
	const year = time.Hour * 24 * 365
	const month = time.Hour * 24 * 30

	var results []string
	age := time.Since(t)

	ageInYears := age / year
	if ageInYears == 1 {
		results = append(results, fmt.Sprintf("%d year", ageInYears))
	} else if ageInYears > 1 {
		results = append(results, fmt.Sprintf("%d years", ageInYears))
	}
	age = age % year

	ageInMonth := age / month
	if ageInMonth == 1 {
		results = append(results, fmt.Sprintf("%d month", ageInMonth))
	} else if ageInMonth > 1 {
		results = append(results, fmt.Sprintf("%d months", ageInMonth))
	}

	return strings.Join(results, " and ") + " old"

}
