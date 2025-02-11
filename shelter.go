package main

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/alexedwards/scs/v2"
)

type ShelterRole string

const (
	ShelterRoleSuperAdmin ShelterRole = "super_admin"
	ShelterRoleAdmin      ShelterRole = "admin"
	ShelterRoleEditor     ShelterRole = "editor"
)

type Shelter struct {
	ID          string
	Name        string
	AvatarURL   *string
	Address     string
	Coordinates *Coordinates
	Description string
	CreatedAt   time.Time
	UpdatedAt   time.Time
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

type ShelterHandler struct {
	Log                  *slog.Logger
	PageTemplateRenderer PageTemplateRenderer
	SessionManager       *scs.SessionManager
	UserSheltersFinder   interface {
		FindSheltersByUserID(ctx context.Context, userID string) ([]*ShelterWithRole, error)
	}
}

type ShelterWithRole struct {
	Role ShelterRole
	Shelter
}

func (s *ShelterHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	flash, _ := PopSessionFlash(s.SessionManager, r.Context())
	userSession, _ := GetSessionUser(s.SessionManager, r.Context())

	shelters, err := s.UserSheltersFinder.FindSheltersByUserID(r.Context(), userSession.UserID)
	if err != nil {
		s.Log.Error("Unable to query for shelter by user id.", "reason", err.Error())
		flash = &Flash{
			Message: "Something went wrong. Please try again later.",
			Level:   FlashLevelError,
		}
	}

	err = s.PageTemplateRenderer.RenderPageTemplate(w, "shelters.html", ShelterPage{
		BasePage: BasePage{
			SessionUser: userSession,
		},
		Flash:          flash,
		ManagedShelter: shelters,
	})
	if err != nil {
		panic(err)
	}
}

type ShelterPage struct {
	BasePage
	Flash          *Flash
	ManagedShelter []*ShelterWithRole
}

type ShelterRegistrationHandler struct {
	Log                     *slog.Logger
	PageTemplateRenderer    PageTemplateRenderer
	SessionManager          *scs.SessionManager
	UnauthorizedRedirectURL string
}

func (s *ShelterRegistrationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sessionUser, _ := GetSessionUser(s.SessionManager, r.Context())
	if sessionUser == nil {
		s.Log.Debug("User unauthorized. Redirecting request.")
		flash := NewFlash("Unauthorized, Please signup first.", FlashLevelError)
		s.SessionManager.Put(r.Context(), SessionKeyFlash, flash)
		http.Redirect(w, r, s.UnauthorizedRedirectURL, http.StatusSeeOther)
		return
	}

	r, _ = http.NewRequest(r.Method, r.URL.String(), nil)
	err := s.PageTemplateRenderer.RenderPageTemplate(w, "shelter_registration.html", ShelterRegistrationPage{
		BasePage: BasePage{
			SessionUser: sessionUser,
		},
		Form: NewShelterRegistrationForm(r),
	})
	if err != nil {
		panic(err)
	}
}

type ShelterRegistrationPage struct {
	BasePage
	Flash *Flash
	Form  ShelterRegistrationForm
}

type ShelterRegistrationForm struct {
	Name                string
	LocationAddress     string
	LocationCoordinates string
	Description         string

	*FieldValidation
}

func NewShelterRegistrationForm(r *http.Request) ShelterRegistrationForm {
	return ShelterRegistrationForm{
		Name:                r.FormValue("name"),
		LocationCoordinates: r.FormValue("location-coordinates"),
		LocationAddress:     r.FormValue("location-address"),
		Description:         r.FormValue("description"),
		FieldValidation:     NewFieldValidation(),
	}
}

type DoShelterRegistrationHandler struct {
	Log                  *slog.Logger
	PageTemplateRenderer PageTemplateRenderer
	SessionManager       *scs.SessionManager
	ShelterCreator       interface {
		CreateShelter(ctx context.Context, userID string, data NewShelter) (*Shelter, error)
	}
	UnauthorizedRedirectURL string
	SuccessRedirectURL      string

	shelterRegistrationTemplateCache *template.Template
}

type NewShelter struct {
	Name        string
	Coordinates Coordinates
	Address     string
	Description string
}

func (d *DoShelterRegistrationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	loginSession, _ := GetSessionUser(d.SessionManager, r.Context())
	if loginSession == nil {
		flash := NewFlash("Unauthorized, Please signup first.", FlashLevelError)
		d.SessionManager.Put(r.Context(), SessionKeyFlash, flash)
		http.Redirect(w, r, d.UnauthorizedRedirectURL, http.StatusSeeOther)
		return
	}

	form := NewShelterRegistrationForm(r)

	form.Check(form.Name == "", "name", "Please fill out this field.")
	form.Check(len(form.Name) < 8, "name", "Value must be at least 8 characters long.")
	form.Check(len(form.Name) > 50, "name", "Value must not exceed 50 characters long.")
	form.Check(form.LocationAddress == "" || form.LocationCoordinates == "", "location", "Please fill out this field")
	form.Check(IsInvalidCoordinates(form.LocationCoordinates), "location", "Coordinates is invalid.")
	form.Check(len(form.LocationAddress) < 8, "location", "Address is too short. Please include more information.")
	form.Check(len(form.LocationAddress) > 250, "location", "Address is too long. It must not exceed 250 characters long.")
	form.Check(form.Description == "", "description", "Please fill out this field.")
	form.Check(len(form.Description) < 250, "description", "Value is too short. It must be at least 250 characters long.")
	form.Check(len(form.Description) > 2500, "description", "Value is too long. It must be not exceed 2,500 characters long.")

	if !form.Valid() {
		d.Log.Debug("Field values validation failed.", "field_errors", form.FieldErrors)
		d.RenderPage(w, ShelterRegistrationPage{
			BasePage: BasePage{
				loginSession,
			},
			Form: form,
		})
		return
	}

	coordinates, _ := ParseCoordinates(form.LocationCoordinates)
	shelter, err := d.ShelterCreator.CreateShelter(r.Context(), loginSession.UserID, NewShelter{
		Name:        form.Name,
		Coordinates: *coordinates,
		Address:     form.LocationAddress,
		Description: form.Description,
	})
	if err != nil {
		d.Log.Error("Unexpected error while trying to register new shelter.", "reason", err.Error())
		d.RenderPage(w, ShelterRegistrationPage{
			BasePage: BasePage{
				loginSession,
			},
			Form: form,
			Flash: &Flash{
				Level:   FlashLevelError,
				Message: "Something went wrong. Please try again later.",
			},
		})
		return
	}

	d.Log.Debug("New shelter was registered.", "shelter_id", shelter.ID)
	flash := NewFlash("Successfully created a new shelter.", FlashLevelSuccess)
	d.SessionManager.Put(r.Context(), SessionKeyFlash, flash)
	redirectURL := strings.ReplaceAll(d.SuccessRedirectURL, "{shelter_id}", shelter.ID)
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

func (d *DoShelterRegistrationHandler) RenderPage(w http.ResponseWriter, data ShelterRegistrationPage) {
	err := d.PageTemplateRenderer.RenderPageTemplate(w, "shelter_registration.html", data)
	if err != nil {
		panic(err)
	}
}

type ShelterByIDPage struct {
	BasePage
	Flash   *Flash
	Role    ShelterRole
	Shelter *Shelter
}

type ShelterByIDHandler struct {
	PageTemplateRenderer PageTemplateRenderer
	SessionManager       *scs.SessionManager
	Log                  *slog.Logger
	NotFoundHandler      http.Handler
	ShelterGetter        ShelterGetter
	ShelterRoleGetter    ShelterRoleGetter
}

func (s *ShelterByIDHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	shelterID := r.PathValue("id")
	flash, _ := PopSessionFlash(s.SessionManager, r.Context())
	sessionUser, _ := GetSessionUser(s.SessionManager, r.Context())

	shelter, err := s.ShelterGetter.GetShelterByID(r.Context(), shelterID)
	if err != nil {
		if errors.Is(err, ErrNoShelter) {
			s.Log.Debug("Shelter was not found.", "shelter_id", shelterID)
			s.NotFoundHandler.ServeHTTP(w, r)
			return
		}

		panic("unable to get shelter with role: " + err.Error())
	}

	var role ShelterRole
	if sessionUser != nil {
		var err error
		role, err = s.ShelterRoleGetter.GetShelterRoleByID(r.Context(), shelterID, sessionUser.UserID)
		if err != nil {
			s.Log.Error("Unexpected error while getting shelter role.", "reason", err.Error())
			flash = &Flash{
				Level:   FlashLevelError,
				Message: "Unexpected error occurred, the result might be incomplete. Please try again later.",
			}
		}
	}

	err = s.PageTemplateRenderer.RenderPageTemplate(w, "shelter_by_id.html", ShelterByIDPage{
		BasePage: BasePage{
			SessionUser: sessionUser,
		},
		Flash:   flash,
		Role:    role,
		Shelter: shelter,
	})
	if err != nil {
		panic(err)
	}
}

type ShelterSettingsHandler struct {
	PageTemplateRenderer PageTemplateRenderer
	Log                  *slog.Logger
	SessionManager       *scs.SessionManager
	NotFoundHandler      http.Handler
	ShelterGetter        ShelterGetter
	ShelterRoleGetter    ShelterRoleGetter
	LoginRedirectURL     string
	ErrorRedirectURL     string
}

func (s *ShelterSettingsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("shelter_id")
	if id == "" {
		s.Log.Debug("No shelter_id path value was provided to handler")
		s.NotFoundHandler.ServeHTTP(w, r)
		return
	}

	sessionUser, _ := GetSessionUser(s.SessionManager, r.Context())
	if sessionUser == nil {
		s.Log.Debug("User is not logged in.")
		flash := NewFlash("Please login first.", FlashLevelError)
		s.SessionManager.Put(r.Context(), SessionKeyFlash, flash)
		url := strings.ReplaceAll(s.LoginRedirectURL, "{shelter_id}", id)
		http.Redirect(w, r, url, http.StatusSeeOther)
		return
	}

	shelter, err := s.ShelterGetter.GetShelterByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrNoShelter) {
			s.Log.Debug("No shelter was found with the given id.", "id", id)
			s.NotFoundHandler.ServeHTTP(w, r)
			return
		}

		s.Log.Error("Unexpected error while getting shelter by id.", "reason", err.Error())
		flash := NewFlash("Something went wrong. Please try again later.", FlashLevelError)
		s.SessionManager.Put(r.Context(), SessionKeyFlash, flash)
		url := strings.ReplaceAll(s.ErrorRedirectURL, "{shelter_id}", id)
		http.Redirect(w, r, url, http.StatusSeeOther)
		return
	}

	role, err := s.ShelterRoleGetter.GetShelterRoleByID(r.Context(), shelter.ID, sessionUser.UserID)
	if err != nil {
		if errors.Is(err, ErrNoShelterRole) {
			s.Log.Debug("User has no role for this shelter.")
			BasicHTTPError(w, http.StatusUnauthorized)
			return
		}

		s.Log.Error("Unexpected error while getting shelter role by id.", "reason", err.Error())
		flash := NewFlash("Something went wrong. Please try again later.", FlashLevelError)
		s.SessionManager.Put(r.Context(), SessionKeyFlash, flash)
		url := strings.ReplaceAll(s.ErrorRedirectURL, "{shelter_id}", id)
		http.Redirect(w, r, url, http.StatusSeeOther)
		return
	}

	err = s.PageTemplateRenderer.RenderPageTemplate(w, "shelter_settings.html", ShelterSettingsPage{
		BasePage: BasePage{
			SessionUser: sessionUser,
		},
		Role:        role,
		ShelterID:   shelter.ID,
		ShelterName: shelter.Name,
	})
	if err != nil {
		panic(err)
	}
}

type ShelterSettingsPage struct {
	BasePage

	Flash       *Flash
	Role        ShelterRole
	ShelterID   string
	ShelterName string
}

var ErrNoShelter = errors.New("no shelter found")

type ShelterGetter interface {
	GetShelterByID(ctx context.Context, shelterID string) (*Shelter, error)
}

var ErrNoShelterRole = errors.New("no shelter role found")

type ShelterRoleGetter interface {
	GetShelterRoleByID(ctx context.Context, shelterID, userID string) (ShelterRole, error)
}
