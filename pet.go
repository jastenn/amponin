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

type FindPetHandler struct {
	Log          *slog.Logger
	SessionStore *CookieSessionStore
	PetFinder    PetFinder
}

type FindQueryResult struct {
	Pet      *Pet
	Distance int
	Address  string
}

type RawFindQueryFilter struct {
	Location string
	Type     string
}

type FindQueryFilter struct {
	Location    Coordinates
	Type        *PetType
	MaxDistance *int
}

type PetFinder interface {
	FindPet(context.Context, FindQueryFilter) ([]*FindQueryResult, error)
}

type findPetPageData struct {
	basePageData
	FormError string
	Flash     *flash
	Filter    RawFindQueryFilter
	Result    []*FindQueryResult
}

var findPetPage = template.Must(template.New("find pets").
	Funcs(template.FuncMap{
		"fmt_distance": fmtDistance,
	}).
	ParseFS(embedFS, "templates/pages/pet/find.html", "templates/pages/base.html"))

func (f *FindPetHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var loginSessionData *loginSession
	f.SessionStore.Decode(r, sessionKeyLoginSession, &loginSessionData)

	rawFilter := RawFindQueryFilter{
		Location: r.FormValue("location"),
		Type:     r.FormValue("type"),
	}

	location, err := ParseCoordinates(rawFilter.Location)
	if err != nil {
		f.Log.Error("Unable to parse coordinates.", "error", err.Error())
		message := "Invalid coordinates."
		if r.FormValue("location") == "" {
			message = "Coordinates is required."
		}
		f.renderPage(w, http.StatusUnprocessableEntity, findPetPageData{
			basePageData: basePageData{
				LoginSession: loginSessionData,
			},
			Filter:    rawFilter,
			FormError: message,
			Result:    nil,
		})
		return
	}

	var petType PetType
	if parsed := PetType(rawFilter.Type); parsed == PetTypeCat || parsed == PetTypeDog {
		petType = parsed
	}

	pets, err := f.PetFinder.FindPet(r.Context(), FindQueryFilter{
		Location: *location,
		Type:     &petType,
	})
	if err != nil {
		f.Log.Error("Unable to find pets.", "error", err.Error())
		f.renderPage(w, http.StatusInternalServerError, findPetPageData{
			basePageData: basePageData{
				LoginSession: loginSessionData,
			},
			Flash:  newFlash(flashLevelError, clientMessageUnexpectedError),
			Filter: rawFilter,
		})
		return
	}

	f.renderPage(w, http.StatusOK, findPetPageData{
		basePageData: basePageData{
			LoginSession: loginSessionData,
		},
		Result: pets,
		Filter: rawFilter,
	})
}

func (f *FindPetHandler) renderPage(w http.ResponseWriter, status int, data findPetPageData) {
	err := RenderPage(w, findPetPage, status, data)
	if err != nil {
		f.Log.Error("Unable to render page.", "error", err.Error())
		renderErrorPage(w, errorPageData{
			basePageData: data.basePageData,
			Status:       http.StatusInternalServerError,
			Message:      clientMessageUnexpectedError,
		})
		return
	}
}

func fmtDistance(meters int) string {
	kilometer := float64(meters) / 1000

	return fmt.Sprintf("%.2f KM", kilometer)
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
