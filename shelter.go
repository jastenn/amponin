package main

import (
	"context"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"time"
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
	Coordinates Coordinates
	Address     string
	Description string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type ShelterTemplateData struct {
	Flash          *Flash
	LoginSession   *LoginSession
	ManagedShelter []*Shelter
}

type ShelterHandler struct {
	Log               *slog.Logger
	TemplateFS        fs.FS
	SessionStore      *CookieStore
	UserSheltersFinder interface {
		FindSheltersByUserID(ctx context.Context, userID string) ([]*Shelter, error)
	}

	shelterTemplateCache *template.Template
}

func (s *ShelterHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	flash, _ := s.SessionStore.Flash(w, r)
	loginSession, _ := GetLoginSession(s.SessionStore, w, r)
	if s.shelterTemplateCache == nil {
		var err error
		s.shelterTemplateCache, err = template.ParseFS(s.TemplateFS, "base.html", "shelter.html")
		if err != nil {
			panic("failed to parse shelter template: " + err.Error())
		}
	}

	shelters, err := s.UserSheltersFinder.FindSheltersByUserID(r.Context(), loginSession.UserID)
	if err != nil {
		s.Log.Error("Unable to query for shelter by user id.", "reason", err.Error())
		flash = &Flash{
			Message: "Something went wrong. Please try again later.",
			Level:   FlashLevelError,
		}
	}

	err = ExecuteTemplate(s.shelterTemplateCache, w, "base.html", ShelterTemplateData{
		Flash:          flash,
		LoginSession:   loginSession,
		ManagedShelter: shelters,
	})
	if err != nil {
		panic("failed to execute shelter template: " + err.Error())
	}
}

type ShelterRegistrationTemplateData struct {
	LoginSession *LoginSession
	Flash        *Flash
	Values       ShelterRegistrationValues
	Errors       ShelterRegistrationErrors
}

type ShelterRegistrationValues struct {
	Name                string
	LocationAddress     string
	LocationCoordinates string
	Description         string
}

type ShelterRegistrationErrors struct {
	Name        string
	Location    string
	Description string
}

func ValidateShelterRegistrationValues(values ShelterRegistrationValues) (errors ShelterRegistrationErrors, ok bool) {
	if l := len(values.Name); l == 0 {
		errors.Name = "Please fill out this field."
	} else if l < 8 {
		errors.Name = "Value must be at least 8 characters long."
	} else if l > 50 {
		errors.Name = "Value must not exceed 50 characters long."
	}

	if values.LocationCoordinates == "" || values.LocationAddress == "" {
		errors.Location = "Please fill out this field."
	} else if _, err := ParseCoordinates(values.LocationCoordinates); err != nil {
		errors.Location = "Coordinates is invalid."
	} else if addressLength := len(values.LocationAddress); addressLength < 8 {
		errors.Location = "Address is too short. Please include more information"
	} else if addressLength > 250 {
		errors.Location = "Address is too long. It must not exceed 250 characters long."
	}

	if l := len(values.Description); l == 0 {
		errors.Description = "Please fill out this field."
		ok = false
	} else if l < 250 {
		errors.Description = "Value is too short. It must be at least 250 characters long."
	} else if l > 2500 {
		errors.Description = "Value is too long. It must not exceed 2,500 characters long."
	}

	if errors.Name != "" ||
		errors.Location != "" ||
		errors.Description != "" {

		return errors, false
	}

	return ShelterRegistrationErrors{}, true
}

type ShelterRegistrationHandler struct {
	TemplateFS              fs.FS
	SessionStore            *CookieStore
	UnauthorizedRedirectURL string

	shelterRegisterTemplateCache *template.Template
}

func (s *ShelterRegistrationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	loginSession, _ := GetLoginSession(s.SessionStore, w, r)
	if loginSession == nil {
		s.SessionStore.SetFlash(w, "Unauthorized, Please signup first.", FlashLevelError)
		http.Redirect(w, r, s.UnauthorizedRedirectURL, http.StatusSeeOther)
		return
	}

	if s.shelterRegisterTemplateCache == nil {
		var err error
		s.shelterRegisterTemplateCache, err = template.ParseFS(s.TemplateFS, "base.html", "shelter-registration.html")
		if err != nil {
			panic("failed to parse shelter template: " + err.Error())
		}
	}
	err := ExecuteTemplate(s.shelterRegisterTemplateCache, w, "base.html", ShelterRegistrationTemplateData{
		LoginSession: loginSession,
	})
	if err != nil {
		panic("failed to execute shelter template: " + err.Error())
	}
}

type NewShelter struct {
	Name        string
	Coordinates Coordinates
	Address     string
	Description string
}

type DoShelterRegistrationHandler struct {
	Log            *slog.Logger
	TemplateFS     fs.FS
	SessionStore   *CookieStore
	ShelterCreator interface {
		CreateShelter(ctx context.Context, userID string, data NewShelter) (*Shelter, error)
	}
	UnauthorizedRedirectURL string
	SuccessRedirect         string

	shelterRegistrationTemplateCache *template.Template
}

func (d *DoShelterRegistrationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	loginSession, _ := GetLoginSession(d.SessionStore, w, r)
	if loginSession == nil {
		d.SessionStore.SetFlash(w, "Unauthorized, Please signup first.", FlashLevelError)
		http.Redirect(w, r, d.UnauthorizedRedirectURL, http.StatusSeeOther)
		return
	}

	fieldValues := ShelterRegistrationValues{
		Name:                r.FormValue("name"),
		LocationCoordinates: r.FormValue("location-coordinates"),
		LocationAddress:     r.FormValue("location-address"),
		Description:         r.FormValue("description"),
	}
	fieldErrors, ok := ValidateShelterRegistrationValues(fieldValues)
	if !ok {
		d.Log.Debug("Field values validation failed.", "field_values", fieldValues)
		d.RenderTemplate(w, ShelterRegistrationTemplateData{
			LoginSession: loginSession,
			Values:       fieldValues,
			Errors:       fieldErrors,
		})
		return
	}

	coordinates, _ := ParseCoordinates(fieldValues.LocationCoordinates)
	shelter, err := d.ShelterCreator.CreateShelter(r.Context(), loginSession.UserID, NewShelter{
		Name:        fieldValues.Name,
		Coordinates: *coordinates,
		Address:     fieldValues.LocationAddress,
		Description: fieldValues.Description,
	})
	if err != nil {
		d.Log.Error("Unexpected error while trying to register new shelter.", "reason", err.Error())
		d.RenderTemplate(w, ShelterRegistrationTemplateData{
			LoginSession: loginSession,
			Values:       fieldValues,
			Flash: &Flash{
				Level:   FlashLevelError,
				Message: "Something went wrong. Please try again later.",
			},
		})
		return
	}

	d.Log.Debug("New shelter was registered.", "shelter_id", shelter.ID)
	d.SessionStore.SetFlash(w, "Successfully created a new shelter.", FlashLevelSuccess)
	http.Redirect(w, r, d.SuccessRedirect, http.StatusSeeOther)
}

func (d *DoShelterRegistrationHandler) RenderTemplate(w http.ResponseWriter, data ShelterRegistrationTemplateData) {
	if d.shelterRegistrationTemplateCache == nil {
		var err error
		d.shelterRegistrationTemplateCache, err = template.ParseFS(
			d.TemplateFS,
			"base.html", "shelter-registration.html",
		)
		if err != nil {
			panic("failed to parse shelter registration template: " + err.Error())
		}
	}

	err := ExecuteTemplate(d.shelterRegistrationTemplateCache, w, "base.html", data)
	if err != nil {
		panic("failed to execute shelter registration template: " + err.Error())
	}
}
