package main

import (
	"context"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
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
	Address     string
	Coordinates Coordinates
	Description string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type Coordinates struct {
	Latitude float64
	Longtude float64
}

func ParseCoordinates(s string) (*Coordinates, error) {
	values := strings.Split(s, " ")
	if len(values) != 2 {
		return nil, fmt.Errorf("unable to parse value as coordinates")
	}

	lat, err := strconv.ParseFloat(values[0], 64)
	if err != nil || lat > 90 || lat < -90 {
		return nil, fmt.Errorf("first value is invalid latitude.")
	}

	lng, err := strconv.ParseFloat(values[1], 64)
	if err != nil || lng > 180 || lng < -180 {
		return nil, fmt.Errorf("second value is invalid longitude.")
	}

	return &Coordinates{
		Latitude: lat,
		Longtude: lng,
	}, nil
}

type RegisterShelterHandler struct {
	Log             *slog.Logger
	SessionStore    *CookieSessionStore
	ShelterRegistry ShelterRegistry
}

type NewShelter struct {
	Name        string
	Address     string
	Coordinates Coordinates
	Description string
}

type ShelterRegistry interface {
	RegisterShelter(ctx context.Context, userID string, data NewShelter) (*Shelter, error)
}

type registerShelterPageData struct {
	basePageData
	Flash       *flash
	FieldValues registerShelterValues
	FieldErrors registerShelterErrors
}

type registerShelterValues struct {
	Name        string
	Address     string
	Coordinates string
	Description string
}

type registerShelterErrors struct {
	Name        string
	Address     string
	Coordinates string
	Description string
}

var registerShelterPage = template.Must(template.ParseFS(embedFS, "templates/pages/shelter/register.html", "templates/pages/base.html"))

func (rh *RegisterShelterHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var loginSessionData *loginSession
	rh.SessionStore.Decode(r, sessionKeyLoginSession, &loginSessionData)

	if loginSessionData == nil {
		status := http.StatusUnauthorized
		rh.Log.Debug("Unauthorized. User is not logged in.")
		renderErrorPage(w, errorPageData{
			Status:  status,
			Message: "Unauthorized. Please login first.",
		})
		return
	}

	if r.Method == http.MethodPost {
		fieldValues := registerShelterValues{
			Name:        r.FormValue("name"),
			Address:     r.FormValue("address"),
			Coordinates: r.FormValue("coordinates"),
			Description: r.FormValue("description"),
		}

		fieldErrors, valid := rh.validate(fieldValues)
		if !valid {
			rh.renderPage(w, http.StatusOK, registerShelterPageData{
				basePageData: basePageData{
					LoginSession: loginSessionData,
				},
				Flash:       nil,
				FieldValues: fieldValues,
				FieldErrors: fieldErrors,
			})
			return
		}

		coordinates, _ := ParseCoordinates(fieldValues.Coordinates)

		shelter, err := rh.ShelterRegistry.RegisterShelter(r.Context(), loginSessionData.UserID, NewShelter{
			Name:        fieldValues.Name,
			Address:     fieldValues.Address,
			Coordinates: *coordinates,
			Description: fieldValues.Description,
		})
		if err != nil {
			rh.Log.Error("Unexpected error while registering a new shelter.", "error", err.Error())
			rh.renderPage(w, http.StatusInternalServerError, registerShelterPageData{
				basePageData: basePageData{
					LoginSession: loginSessionData,
				},
				Flash:       NewFlash(flashLevelError, clientMessageUnexpectedError),
				FieldValues: fieldValues,
			})
			return
		}

		rh.Log.Info("New shelter was created.", "shelter_id", shelter.ID, "user_id", loginSessionData.UserID)
		rh.renderPage(w, http.StatusOK, registerShelterPageData{
			basePageData: basePageData{
				LoginSession: loginSessionData,
			},
			Flash: NewFlash(flashLevelSuccess, "Successfully registered a new shelter."),
		})
		return
	}

	rh.renderPage(w, http.StatusOK, registerShelterPageData{
		basePageData: basePageData{
			LoginSession: loginSessionData,
		},
		Flash: nil,
	})
}

func (rh *RegisterShelterHandler) validate(fieldValues registerShelterValues) (fieldErrors registerShelterErrors, valid bool) {
	if l := len(strings.TrimSpace(fieldValues.Name)); l == 0 {
		fieldErrors.Name = "Please fill out this field."
	} else if l < 8 {
		fieldErrors.Name = "Value must be at least 8 characters long."
	} else if l > 50 {
		fieldErrors.Name = "Value must not exceed 50 characters long."
	}

	if l := len(strings.TrimSpace(fieldValues.Address)); l == 0 {
		fieldErrors.Address = "Please fill out this field."
	} else if l < 8 {
		fieldErrors.Address = "Value is too short. Please include more information."
	} else if l > 120 {
		fieldErrors.Address = "Value must not exceed 120 characters long."
	}

	if fieldValues.Coordinates == "" {
		fieldErrors.Coordinates = "Please fill out this field."
	} else if _, err := ParseCoordinates(fieldValues.Coordinates); err != nil {
		fieldErrors.Coordinates = "Value is invalid coordinates."
	}

	if l := len(strings.TrimSpace(fieldValues.Description)); l == 0 {
		fieldErrors.Description = "Please fill out this field."
	} else if l < 150 {
		fieldErrors.Description = "Value must be at least 150 characters long."
	} else if l > 2500 {
		fieldErrors.Description = "Value must not exceed 2500 characters long."
	}

	if fieldErrors.Name != "" ||
		fieldErrors.Address != "" ||
		fieldErrors.Coordinates != "" ||
		fieldErrors.Description != "" {

		return fieldErrors, false
	}

	return registerShelterErrors{}, true
}

func (rh *RegisterShelterHandler) renderPage(w http.ResponseWriter, status int, data registerShelterPageData) {
	err := RenderPage(w, registerShelterPage, http.StatusOK, data)
	if err != nil {
		rh.Log.Error("Unexpected error while rendering page.", "error", err.Error())
		renderErrorPage(w, errorPageData{
			basePageData: data.basePageData,
			Status:       http.StatusInternalServerError,
			Message:      clientMessageUnexpectedError,
		})
		return
	}
}
