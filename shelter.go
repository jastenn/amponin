package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path"
	"slices"
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

func (s ShelterRole) String() string {
	switch s {
	case ShelterRoleSuperAdmin:
		return "Super Admin"
	case ShelterRoleAdmin:
		return "Admin"
	case ShelterRoleEditor:
		return "Editor"
	}

	return string(s)
}

type Shelter struct {
	ID          string
	Name        string
	AvatarURL   *string
	Address     string
	Coordinates Coordinates
	Description string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type Coordinates struct {
	Longitude float64
	Latitude  float64
}

func (c Coordinates) String() string {
	return fmt.Sprintf("%v,%v", c.Latitude, c.Longitude)
}

func ParseCoordinates(s string) (Coordinates, error) {
	xs := strings.Split(s, ",")
	if len(xs) != 2 {
		return Coordinates{}, errors.New("invalid coordinates")
	}

	lat, err := strconv.ParseFloat(xs[0], 64)
	if err != nil {
		return Coordinates{}, fmt.Errorf("invalid coordinates: latitude is invalid: %w", err)
	}
	if lat > 90 || lat < -90 {
		return Coordinates{}, fmt.Errorf("invalid coordinates: latitude out of bounds")
	}

	lng, err := strconv.ParseFloat(xs[1], 64)
	if err != nil {
		return Coordinates{}, fmt.Errorf("invalid coordinates: longitude is invalid float: %w", err)
	}
	if lng > 180 || lng < -180 {
		return Coordinates{}, fmt.Errorf("invalid coordinates: latitude out of bounds")
	}

	return Coordinates{
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
	userSession := GetSessionUser(r.Context())
	if userSession == nil {
		s.Log.Debug("Unauthorized request.")
		BasicHTTPError(w, http.StatusUnauthorized)
		return
	}

	shelters, err := s.UserSheltersFinder.FindSheltersByUserID(r.Context(), userSession.UserID)
	if err != nil {
		s.Log.Error("Unable to query for shelter by user id.", "reason", err.Error())
		flash := NewFlash("Something went wrong. Please try again later.", FlashLevelError)
		err = s.PageTemplateRenderer.RenderPageTemplate(w, "shelters.html", ShelterPage{
			BasePage: BasePage{
				SessionUser: userSession,
			},
			Flash: flash,
		})
		if err != nil {
			panic(err)
		}
	}

	flash, _ := PopSessionFlash(s.SessionManager, r.Context())
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
	Log                  *slog.Logger
	PageTemplateRenderer PageTemplateRenderer
	SessionManager       *scs.SessionManager
}

func (s *ShelterRegistrationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sessionUser := GetSessionUser(r.Context())
	if sessionUser == nil {
		s.Log.Debug("Unauthorized request.")
		BasicHTTPError(w, http.StatusUnauthorized)
		return
	}

	r, _ = http.NewRequest(r.Method, r.URL.String(), nil)
	err := s.PageTemplateRenderer.RenderPageTemplate(w, "shelter_registration.html", ShelterRegistrationPage{
		BasePage: BasePage{
			SessionUser: sessionUser,
		},
		Form: NewShelterRegistrationFormFromRequest(r),
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

func NewShelterRegistrationFormFromRequest(r *http.Request) ShelterRegistrationForm {
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
	SuccessRedirectURL string
}

type NewShelter struct {
	Name        string
	Coordinates Coordinates
	Address     string
	Description string
}

func (d *DoShelterRegistrationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sessionUser := GetSessionUser(r.Context())
	if sessionUser == nil {
		d.Log.Debug("Unauthorized request.")
		BasicHTTPError(w, http.StatusUnauthorized)
		return
	}

	form := NewShelterRegistrationFormFromRequest(r)

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
				sessionUser,
			},
			Form: form,
		})
		return
	}

	coordinates, _ := ParseCoordinates(form.LocationCoordinates)
	shelter, err := d.ShelterCreator.CreateShelter(r.Context(), sessionUser.UserID, NewShelter{
		Name:        form.Name,
		Coordinates: coordinates,
		Address:     form.LocationAddress,
		Description: form.Description,
	})
	if err != nil {
		d.Log.Error("Unexpected error while trying to register new shelter.", "reason", err.Error())
		d.RenderPage(w, ShelterRegistrationPage{
			BasePage: BasePage{
				sessionUser,
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

var ErrNoShelter = errors.New("no shelter found")

type ShelterGetter interface {
	GetShelterByID(ctx context.Context, shelterID string) (*Shelter, error)
}

var ErrNoShelterRole = errors.New("no shelter role found")

type ShelterRoleGetter interface {
	GetShelterRoleByID(ctx context.Context, shelterID, userID string) (ShelterRole, error)
}

type ShelterRoleGetterByEmail interface {
	GetShelterRoleByEmail(ctx context.Context, shelterID, email string) (ShelterRole, error)
}

func (s *ShelterByIDHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	shelterID := r.PathValue("shelter_id")

	shelter, err := s.ShelterGetter.GetShelterByID(r.Context(), shelterID)
	if err != nil {
		if errors.Is(err, ErrNoShelter) {
			s.Log.Debug("Shelter was not found.", "shelter_id", shelterID)
			s.NotFoundHandler.ServeHTTP(w, r)
			return
		}

		s.Log.Error("Unable to get shelter with role.", "reason", err.Error())
		BasicHTTPError(w, http.StatusInternalServerError)
		return
	}

	sessionUser := GetSessionUser(r.Context())
	var role ShelterRole
	if sessionUser != nil {
		var err error
		role, err = s.ShelterRoleGetter.GetShelterRoleByID(r.Context(), shelterID, sessionUser.UserID)
		if err != nil {
			s.Log.Error("Unexpected error while getting shelter role.", "reason", err.Error())
			BasicHTTPError(w, http.StatusInternalServerError)
			return
		}
	}

	flash, _ := PopSessionFlash(s.SessionManager, r.Context())
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
}

func (s *ShelterSettingsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sessionUser := GetSessionUser(r.Context())
	if sessionUser == nil {
		s.Log.Debug("Unauthorized request.")
		BasicHTTPError(w, http.StatusUnauthorized)
		return
	}

	shelterID := r.PathValue("shelter_id")

	shelter, err := s.ShelterGetter.GetShelterByID(r.Context(), shelterID)
	if err != nil {
		if errors.Is(err, ErrNoShelter) {
			s.Log.Debug("No shelter was found with the given id.", "id", shelterID)
			s.NotFoundHandler.ServeHTTP(w, r)
			return
		}

		s.Log.Error("Unexpected error while getting shelter by id.", "reason", err.Error())
		BasicHTTPError(w, http.StatusInternalServerError)
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
		BasicHTTPError(w, http.StatusInternalServerError)
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

type ShelterUpdateHandler struct {
	Log                  *slog.Logger
	PageTemplateRenderer PageTemplateRenderer
	SessionManager       *scs.SessionManager
	NotFoundHandler      http.Handler
	ShelterGetter        ShelterGetter
	ShelterRoleGetter    ShelterRoleGetter
}

func (s *ShelterUpdateHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sessionUser := GetSessionUser(r.Context())
	if sessionUser == nil {
		s.Log.Debug("Unauthorized request.")
		BasicHTTPError(w, http.StatusServiceUnavailable)
		return
	}

	shelterID := r.PathValue("shelter_id")

	role, err := s.ShelterRoleGetter.GetShelterRoleByID(r.Context(), shelterID, sessionUser.UserID)
	if err != nil {
		if errors.Is(err, ErrNoShelterRole) {
			s.Log.Debug("No shelter role was found associated with this user.", "user_id", sessionUser.UserID, "shelter_id", shelterID)
			BasicHTTPError(w, http.StatusServiceUnavailable)
			return
		}

		s.Log.Error(
			"Unexpected error while getting shelter role associated to user.",
			"user_id", sessionUser.UserID,
			"shelter_id", shelterID,
		)
		BasicHTTPError(w, http.StatusInternalServerError)
		return
	}

	allowedRoles := []ShelterRole{ShelterRoleAdmin, ShelterRoleSuperAdmin, ShelterRoleEditor}
	if !slices.Contains(allowedRoles, role) {
		s.Log.Debug("User's role is not allowed to take this action", "role", role)
		BasicHTTPError(w, http.StatusUnauthorized)
		return
	}

	shelter, err := s.ShelterGetter.GetShelterByID(r.Context(), shelterID)
	if err != nil {
		s.Log.Error("Unexpected error while shelter with id.", "shelter_id", shelterID)
		BasicHTTPError(w, http.StatusInternalServerError)
		return
	}

	flash, _ := PopSessionFlash(s.SessionManager, r.Context())
	err = s.PageTemplateRenderer.RenderPageTemplate(
		w,
		"shelter_update.html",
		ShelterUpdatePage{
			BasePage: BasePage{
				SessionUser: sessionUser,
			},
			Flash:       flash,
			ShelterID:   shelter.ID,
			ShelterName: shelter.Name,
			Form: ShelterUpdateForm{
				Name:            shelter.Name,
				Coordinates:     shelter.Coordinates.String(),
				Address:         shelter.Address,
				Description:     shelter.Description,
				FieldValidation: NewFieldValidation(),
			},
		},
	)
	if err != nil {
		panic(err)
	}
}

type DoShelterUpdateHandler struct {
	Log                  *slog.Logger
	PageTemplateRenderer PageTemplateRenderer
	SessionManager       *scs.SessionManager
	NotFoundHandler      http.Handler
	FileStore            FileStore
	ShelterRoleGetter    ShelterRoleGetter
	ShelterGetter        ShelterGetter
	ShelterUpdater       interface {
		UpdateShelter(ctx context.Context, shelterID string, data ShelterUpdate) (*Shelter, error)
	}
	SuccessRedirectURL string
}

type ShelterUpdate struct {
	Avatar      *string
	Name        *string
	Coordinates *Coordinates
	Address     *string
	Description *string
}

func (d *DoShelterUpdateHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sessionUser := GetSessionUser(r.Context())
	if sessionUser == nil {
		d.Log.Debug("Unauthorized request.")
		BasicHTTPError(w, http.StatusUnauthorized)
		return
	}

	shelterID := r.PathValue("shelter_id")
	role, err := d.ShelterRoleGetter.GetShelterRoleByID(r.Context(), shelterID, sessionUser.UserID)
	if err != nil {
		if errors.Is(err, ErrNoShelterRole) {
			d.Log.Debug("No shelter role was found associated with this user.", "user_id", sessionUser.UserID, "shelter_id", shelterID)
			d.NotFoundHandler.ServeHTTP(w, r)
			return
		}

		d.Log.Error("Unexpected error while getting shelter role associated to user.", "user_id", sessionUser.UserID, "shelter_id", shelterID)
		BasicHTTPError(w, http.StatusInternalServerError)
		return
	}

	allowedRoles := []ShelterRole{ShelterRoleAdmin, ShelterRoleSuperAdmin, ShelterRoleEditor}
	if !slices.Contains(allowedRoles, role) {
		d.Log.Debug("User's role is not allowed to take this action", "role", role)
		BasicHTTPError(w, http.StatusUnauthorized)
		return
	}

	shelter, err := d.ShelterGetter.GetShelterByID(r.Context(), shelterID)
	if err != nil {
		d.Log.Error("Unexpected error while shelter with id.", "shelter_id", shelterID)
		BasicHTTPError(w, http.StatusInternalServerError)
		return
	}

	var form ShelterUpdateForm
	form.FieldValidation = NewFieldValidation()
	if b, filename, err := FormImage(r, "avatar"); err != nil && !errors.Is(err, http.ErrMissingFile) {
		form.Add("avatar", "Unexpected error while parsing this image.")
	} else if !errors.Is(err, http.ErrMissingFile) {
		form.Avatar = &FormImageResult{
			Data:     b,
			Filename: filename,
		}
	}
	form.Name = r.FormValue("name")
	form.Coordinates = r.FormValue("coordinates")
	form.Address = r.FormValue("address")
	form.Description = r.FormValue("description")

	form.Check(form.Name == "", "name", "Please fill out this field.")
	form.Check(len(form.Name) < 8, "name", "Value must be at least 8 characters long.")
	form.Check(len(form.Name) > 50, "name", "Value must not exceed 50 characters long.")
	form.Check(form.Address == "" || form.Coordinates == "", "location", "Please fill out this field")
	form.Check(IsInvalidCoordinates(form.Coordinates), "location", "Coordinates is invalid.")
	form.Check(len(form.Coordinates) < 8, "location", "Address is too short. Please include more information.")
	form.Check(len(form.Coordinates) > 250, "location", "Address is too long. It must not exceed 250 characters long.")
	form.Check(form.Description == "", "description", "Please fill out this field.")
	form.Check(len(form.Description) < 250, "description", "Value is too short. It must be at least 250 characters long.")
	form.Check(len(form.Description) > 2500, "description", "Value is too long. It must be not exceed 2,500 characters long.")

	if !form.Valid() {
		err := d.PageTemplateRenderer.RenderPageTemplate(w, "shelter_update.html", ShelterUpdatePage{
			BasePage: BasePage{
				SessionUser: sessionUser,
			},
			ShelterID:   shelter.ID,
			ShelterName: shelter.Name,
			Form:        form,
		})
		if err != nil {
			panic(err)
		}
		return
	}

	var avatar *string
	if form.Avatar != nil {
		filepath := path.Join("shelters", shelter.ID, form.Avatar.Filename)
		url, err := d.FileStore.Save(filepath, bytes.NewBuffer(form.Avatar.Data))
		if err != nil {
			form.Add("avatar", "Something went wrong while uploading this file.")
			err := d.PageTemplateRenderer.RenderPageTemplate(w, "shelter_update.html", ShelterUpdatePage{
				BasePage: BasePage{
					SessionUser: sessionUser,
				},
				ShelterID:   shelter.ID,
				ShelterName: shelter.Name,
				Form:        form,
			})
			if err != nil {
				panic(err)
			}
			return
		}
		avatar = &url
	}

	coordinates, _ := ParseCoordinates(form.Coordinates)
	_, err = d.ShelterUpdater.UpdateShelter(r.Context(), shelterID, ShelterUpdate{
		Avatar:      avatar,
		Name:        &form.Name,
		Coordinates: &coordinates,
		Address:     &form.Address,
		Description: &form.Description,
	})
	if err != nil {
		d.Log.Error("Unable to update shelter information", "reason", err.Error(), "shelter_id", shelterID, "user_id", sessionUser.UserID)
		err := d.PageTemplateRenderer.RenderPageTemplate(w, "shelter_update.html", ShelterUpdatePage{
			BasePage: BasePage{
				SessionUser: sessionUser,
			},
			ShelterID:   shelter.ID,
			ShelterName: shelter.Name,
			Flash:       NewFlash("Something went wrong. Please try again later.", FlashLevelError),
			Form:        form,
		})
		if err != nil {
			panic(err)
		}
		return
	}

	d.Log.Debug("Successfully updated shelter information.", "shelter_id", shelterID, "user_id", sessionUser.UserID)

	redirectURL := strings.ReplaceAll(d.SuccessRedirectURL, "{shelter_id}", shelterID)
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

type ShelterUpdatePage struct {
	BasePage
	Flash       *Flash
	ShelterID   string
	ShelterName string
	Form        ShelterUpdateForm
}

type ShelterUpdateForm struct {
	Avatar      *FormImageResult
	Name        string
	Coordinates string
	Address     string
	Description string
	*FieldValidation
}

type ShelterRolesHandler struct {
	Log                  *slog.Logger
	PageTemplateRenderer PageTemplateRenderer
	ShelterGetter        ShelterGetter
	ShelterRoleGetter    ShelterRoleGetter
	ShelterRolesFinder   interface {
		FindShelterRoles(ctx context.Context, shelterID string) ([]*FindShelterRolesResult, error)
	}
	SessionManager   *scs.SessionManager
	LoginRedirectURL string
	NotFoundHandler  http.Handler
}

type FindShelterRolesResult struct {
	UserID      string
	DisplayName string
	Email       string
	Role        ShelterRole
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

func (s *ShelterRolesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	shelterID := r.PathValue("shelter_id")
	sessionUser := GetSessionUser(r.Context())
	if sessionUser == nil {
		s.Log.Debug("Unauthorized request.")
		BasicHTTPError(w, http.StatusUnauthorized)
		return
	}

	shelter, err := s.ShelterGetter.GetShelterByID(r.Context(), shelterID)
	if err != nil {
		if errors.Is(err, ErrNoShelter) {
			s.Log.Debug("No shelter found with the given id", "shelter_id", shelterID)
			s.NotFoundHandler.ServeHTTP(w, r)
			return
		}

		s.Log.Error("Unexpected error while getting shelter by id", "shelter_id", shelterID, "reason", err.Error())
		s.RenderPage(w, ShelterRolesPage{
			BasePage: BasePage{
				SessionUser: sessionUser,
			},
			ShelterID:   shelter.ID,
			ShelterName: shelter.Name,
			Flash:       NewFlash("Something went wrong. Please try again later.", FlashLevelError),
		})
		return
	}

	role, err := s.ShelterRoleGetter.GetShelterRoleByID(r.Context(), shelterID, sessionUser.UserID)
	if err != nil {
		if errors.Is(err, ErrNoShelterRole) {
			s.Log.Debug("No shelter role was found associated with this user.", "user_id", sessionUser.UserID, "shelter_id", shelterID)
			s.NotFoundHandler.ServeHTTP(w, r)
			return
		}

		s.Log.Error("Unexpected error while getting shelter role associated to user.", "user_id", sessionUser.UserID, "shelter_id", shelterID)
		flash := NewFlash("Something went wrong. Please try again later.", FlashLevelError)
		s.RenderPage(w, ShelterRolesPage{
			BasePage: BasePage{
				SessionUser: sessionUser,
			},
			Flash:       flash,
			ShelterID:   shelter.ID,
			ShelterName: shelter.Name,
		})
		return
	}

	if role != ShelterRoleAdmin && role != ShelterRoleSuperAdmin {
		s.Log.Debug("Unauthorized request. Should be at least an admin.", "shelter_id", shelter.ID, "user_id", sessionUser.UserID, "role", role)
		BasicHTTPError(w, http.StatusUnauthorized)
		return
	}

	shelterRoles, err := s.ShelterRolesFinder.FindShelterRoles(r.Context(), shelter.ID)
	if err != nil {
		s.Log.Error("Unexpected error while getting shelter roles by id", "shelter_id", shelterID, "reason", err.Error())
		flash := NewFlash("Something went wrong. Please try again later.", FlashLevelError)
		s.RenderPage(w, ShelterRolesPage{
			BasePage: BasePage{
				SessionUser: sessionUser,
			},
			ShelterID:   shelter.ID,
			ShelterName: shelter.Name,
			Flash:       flash,
		})
		return
	}

	s.Log.Debug("Successfully find shelter roles by id.", "roles_count", len(shelterRoles))

	flash, _ := PopSessionFlash(s.SessionManager, r.Context())
	s.RenderPage(w, ShelterRolesPage{
		BasePage: BasePage{
			SessionUser: sessionUser,
		},
		Flash:        flash,
		ShelterID:    shelter.ID,
		ShelterName:  shelter.Name,
		ShelterRoles: shelterRoles,
	})
}

func (s *ShelterRolesHandler) RenderPage(w http.ResponseWriter, data ShelterRolesPage) {
	err := s.PageTemplateRenderer.RenderPageTemplate(w, "shelter_roles.html", data)
	if err != nil {
		panic(err)
	}
}

type ShelterRolesPage struct {
	BasePage
	Flash        *Flash
	ShelterID    string
	ShelterName  string
	ShelterRoles []*FindShelterRolesResult
}

type ShelterAddRoleHandler struct {
	Log                  *slog.Logger
	PageTemplateRenderer PageTemplateRenderer
	ShelterGetter        ShelterGetter
	ShelterRoleGetter    ShelterRoleGetter
	SessionManager       *scs.SessionManager
	NotFoundHandler      http.Handler
}

func (s *ShelterAddRoleHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sessionUser := GetSessionUser(r.Context())
	if sessionUser == nil {
		s.Log.Debug("Unauthorized request.")
		BasicHTTPError(w, http.StatusUnauthorized)
		return
	}

	shelterID := r.PathValue("shelter_id")

	s.Log.Debug("Getting shelter by id.", "shelter_id", shelterID)
	shelter, err := s.ShelterGetter.GetShelterByID(r.Context(), shelterID)
	if err != nil {
		if errors.Is(err, ErrNoShelter) {
			s.Log.Debug("No shelter found with the given id", "shelter_id", shelterID)
			s.NotFoundHandler.ServeHTTP(w, r)
			return
		}

		s.Log.Error("Unexpected error while getting shelter by id.", "shelter_id", shelter.ID)
		BasicHTTPError(w, http.StatusInternalServerError)
		return
	}

	s.Log.Debug("Getting shelter role associated by user.", "shelter_id", shelterID, "user_id", sessionUser.UserID)
	role, err := s.ShelterRoleGetter.GetShelterRoleByID(r.Context(), shelter.ID, sessionUser.UserID)
	if err != nil {
		if errors.Is(err, ErrNoShelterRole) {
			s.Log.Debug("No shelter role was found associated with this user.", "user_id", sessionUser.UserID, "shelter_id", shelterID)
			BasicHTTPError(w, http.StatusUnauthorized)
			return
		}

		s.Log.Error("Unexpected error while getting shelter role by id.", "user_id", sessionUser.UserID, "shelter_id", shelter.ID)
		BasicHTTPError(w, http.StatusInternalServerError)
		return
	}

	if role != ShelterRoleAdmin && role != ShelterRoleSuperAdmin {
		s.Log.Error("Unauthorized. Must be an admin or higher", "user_id", sessionUser.UserID, "shelter_id", shelter.ID, "role", role)
		BasicHTTPError(w, http.StatusUnauthorized)
		return
	}

	flash, _ := PopSessionFlash(s.SessionManager, r.Context())
	err = s.PageTemplateRenderer.RenderPageTemplate(w, "shelter_add_role.html", ShelterAddRolePage{
		BasePage: BasePage{
			SessionUser: sessionUser,
		},
		Flash:       flash,
		ShelterID:   shelter.ID,
		ShelterName: shelter.Name,
		Form:        NewShelterAddRoleForm(),
	})
	if err != nil {
		panic(err)
	}
}

type DoShelterAddRoleHandler struct {
	Log                  *slog.Logger
	PageTemplateRenderer PageTemplateRenderer
	ShelterGetter        ShelterGetter
	ShelterRoleGetter    ShelterRoleGetter
	ShelterRoleCreator   ShelterRoleCreator
	SessionManager       *scs.SessionManager
	NotFoundHandler      http.Handler
	SuccessRedirect      string
}

type NewShelterRole struct {
	ShelterID string
	UserEmail string
	Role      ShelterRole
}

var ErrUserHasRole = errors.New("user already has a role")

type ShelterRoleCreator interface {
	CreateShelterRole(context.Context, NewShelterRole) error
}

func (s *DoShelterAddRoleHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sessionUser := GetSessionUser(r.Context())
	if sessionUser == nil {
		s.Log.Debug("Unauthorized. User is not logged in.")
		BasicHTTPError(w, http.StatusUnauthorized)
		return
	}

	shelterID := r.PathValue("shelter_id")

	s.Log.Debug("Getting shelter by id.", "shelter_id", shelterID)
	shelter, err := s.ShelterGetter.GetShelterByID(r.Context(), shelterID)
	if err != nil {
		if errors.Is(err, ErrNoShelter) {
			s.Log.Debug("No shelter found with the given id", "shelter_id", shelterID)
			s.NotFoundHandler.ServeHTTP(w, r)
			return
		}

		s.Log.Error("Unexpected error while getting shelter by id.", "shelter_id", shelter.ID)
		BasicHTTPError(w, http.StatusInternalServerError)
		return
	}

	s.Log.Debug("Getting shelter role associated by user.", "shelter_id", shelterID, "user_id", sessionUser.UserID)
	role, err := s.ShelterRoleGetter.GetShelterRoleByID(r.Context(), shelter.ID, sessionUser.UserID)
	if err != nil {
		if errors.Is(err, ErrNoShelterRole) {
			s.Log.Debug("No shelter role was found associated with this user.", "user_id", sessionUser.UserID, "shelter_id", shelterID)
			BasicHTTPError(w, http.StatusUnauthorized)
			return
		}

		s.Log.Error("Unexpected error while getting shelter role by id.", "user_id", sessionUser.UserID, "shelter_id", shelter.ID)
		BasicHTTPError(w, http.StatusInternalServerError)
		return
	}

	if role != ShelterRoleAdmin && role != ShelterRoleSuperAdmin {
		s.Log.Error("Unauthorized. Must be an admin or higher", "user_id", sessionUser.UserID, "shelter_id", shelter.ID, "role", role)
		BasicHTTPError(w, http.StatusUnauthorized)
		return
	}

	form := NewShelterAddRoleForm()
	form.Email = r.FormValue("email")
	form.Role = r.FormValue("role")

	form.Check(form.Email == "", "email", "Please fill out this field.")
	form.Check(IsInvalidEmail(form.Email), "email", "Value is invalid email.")
	form.Check(form.Role == "", "role", "Please fill out this field.")
	form.Check(
		form.Role != string(ShelterRoleAdmin) && form.Role != string(ShelterRoleEditor),
		"role",
		"Value is invalid role.",
	)

	if !form.Valid() {
		s.Log.Debug("Field validation failed.", "field_errors", form.FieldErrors)
		s.RenderPage(w, ShelterAddRolePage{
			BasePage: BasePage{
				SessionUser: sessionUser,
			},
			ShelterID:   shelter.ID,
			ShelterName: shelter.Name,
			Form:        form,
		})
		return
	}

	err = s.ShelterRoleCreator.CreateShelterRole(r.Context(), NewShelterRole{
		ShelterID: shelter.ID,
		UserEmail: form.Email,
		Role:      ShelterRole(form.Role),
	})
	if err != nil {
		if errors.Is(err, ErrUserHasRole) {
			s.Log.Debug("User already has an assigned role at the shelter")

			flash := NewFlash("User already has an assigned role.", FlashLevelWarn)
			s.SessionManager.Put(r.Context(), SessionKeyFlash, flash)

			redirectURL := strings.ReplaceAll(s.SuccessRedirect, "{shelter_id}", shelterID)
			http.Redirect(w, r, redirectURL, http.StatusSeeOther)
			return
		}

		if errors.Is(err, ErrNoUser) {
			s.Log.Debug("User doesn't exists.", "user_email", form.Email)
			flash := NewFlash("No user with the given email was found.", FlashLevelError)
			s.RenderPage(w, ShelterAddRolePage{
				BasePage: BasePage{
					SessionUser: sessionUser,
				},
				Flash:       flash,
				ShelterID:   shelter.ID,
				ShelterName: shelter.Name,
				Form:        form,
			})
			return
		}

		s.Log.Error("Unexpected error while creating a role for the shelter.", "shelter_id", shelter.ID, "user_id", sessionUser.UserID, "reason", err.Error())
		flash := NewFlash("Something went wrong. Please try again later.", FlashLevelError)
		s.RenderPage(w, ShelterAddRolePage{
			BasePage: BasePage{
				SessionUser: sessionUser,
			},
			Flash:       flash,
			ShelterID:   shelter.ID,
			ShelterName: shelter.Name,
			Form:        form,
		})
		return
	}

	s.Log.Debug("New shelter role was created.", "shelter_id", shelter.ID, "user_id", sessionUser.UserID, "role", form.Role)

	flash := NewFlash("New shelter role was created.", FlashLevelSuccess)
	s.SessionManager.Put(r.Context(), SessionKeyFlash, flash)

	redirectURL := strings.ReplaceAll(s.SuccessRedirect, "{shelter_id}", shelterID)
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

func (d *DoShelterAddRoleHandler) RenderPage(w io.Writer, data ShelterAddRolePage) {
	err := d.PageTemplateRenderer.RenderPageTemplate(w, "shelter_add_role.html", data)
	if err != nil {
		panic(err)
	}
}

type ShelterAddRolePage struct {
	BasePage
	Flash       *Flash
	ShelterID   string
	ShelterName string
	Form        ShelterAddRoleForm
}

type ShelterAddRoleForm struct {
	Email string
	Role  string
	*FieldValidation
}

func NewShelterAddRoleForm() ShelterAddRoleForm {
	return ShelterAddRoleForm{
		FieldValidation: NewFieldValidation(),
	}
}

type ShelterRemoveRoleHandler struct {
	Log                  *slog.Logger
	PageTemplateRenderer PageTemplateRenderer
	ShelterGetter        ShelterGetter
	ShelterRoleGetter    ShelterRoleGetter
	SessionManager       *scs.SessionManager
	NotFoundHandler      http.Handler
}

func (s *ShelterRemoveRoleHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sessionUser := GetSessionUser(r.Context())
	if sessionUser == nil {
		s.Log.Debug("Unauthorized request.")
		BasicHTTPError(w, http.StatusUnauthorized)
		return
	}

	shelterID := r.PathValue("shelter_id")
	targetEmail := r.URL.Query().Get("email")
	if targetEmail == "" {
		//TODO: Provide a better error handling
		s.Log.Debug("Target email is a required parameter")
		BasicHTTPError(w, http.StatusUnprocessableEntity)
		return
	}

	s.Log.Debug("Getting shelter by id.", "shelter_id", shelterID)
	shelter, err := s.ShelterGetter.GetShelterByID(r.Context(), shelterID)
	if err != nil {
		if errors.Is(err, ErrNoShelter) {
			s.Log.Debug("No shelter found with the given id", "shelter_id", shelterID)
			s.NotFoundHandler.ServeHTTP(w, r)
			return
		}

		s.Log.Error("Unexpected error while getting shelter by id.", "shelter_id", shelter.ID)
		BasicHTTPError(w, http.StatusInternalServerError)
		return
	}

	s.Log.Debug("Getting shelter role associated by user.", "shelter_id", shelterID, "user_id", sessionUser.UserID)
	role, err := s.ShelterRoleGetter.GetShelterRoleByID(r.Context(), shelter.ID, sessionUser.UserID)
	if err != nil {
		if errors.Is(err, ErrNoShelterRole) {
			s.Log.Debug("No shelter role was found associated with this user.", "user_id", sessionUser.UserID, "shelter_id", shelterID)
			BasicHTTPError(w, http.StatusUnauthorized)
			return
		}

		s.Log.Error("Unexpected error while getting shelter role by id.", "user_id", sessionUser.UserID, "shelter_id", shelter.ID)
		BasicHTTPError(w, http.StatusInternalServerError)
		return
	}

	if role != ShelterRoleAdmin && role != ShelterRoleSuperAdmin {
		s.Log.Error("Unauthorized. Must be an admin or higher", "user_id", sessionUser.UserID, "shelter_id", shelter.ID, "role", role)
		BasicHTTPError(w, http.StatusUnauthorized)
		return
	}

	err = s.PageTemplateRenderer.RenderPageTemplate(w, "shelter_remove_role.html", ShelterRemoveRolePage{
		BasePage: BasePage{
			SessionUser: sessionUser,
		},
		ShelterID:   shelter.ID,
		ShelterName: shelter.Name,
		Email:       targetEmail,
		Form:        NewShelterRemoveRoleForm(),
	})
	if err != nil {
		panic(err)
	}
}

type ShelterRemoveRolePage struct {
	BasePage
	Flash       *Flash
	ShelterID   string
	ShelterName string
	Email       string
	Form        ShelterRemoveRoleForm
}

type ShelterRemoveRoleForm struct {
	Confirmation string
	*FieldValidation
}

func NewShelterRemoveRoleForm() ShelterRemoveRoleForm {
	return ShelterRemoveRoleForm{
		FieldValidation: NewFieldValidation(),
	}
}

type DoShelterRemoveRoleHandler struct {
	Log                  *slog.Logger
	PageTemplateRenderer PageTemplateRenderer
	ShelterGetter        ShelterGetter
	ShelterRoleStore     interface {
		ShelterRoleGetter
		ShelterRoleGetterByEmail
	}
	ShelterRoleDeleter ShelterRoleDeleter
	SessionManager     *scs.SessionManager
	NotFoundHandler    http.Handler
	SuccessRedirect    string
}

type ShelterRoleDeleter interface {
	DeleteShelterRole(ctx context.Context, shelterID, email string) error
}

func (d *DoShelterRemoveRoleHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sessionUser := GetSessionUser(r.Context())
	if sessionUser == nil {
		d.Log.Debug("Unauthorized. User is not logged in.")
		BasicHTTPError(w, http.StatusUnauthorized)
		return
	}

	shelterID := r.PathValue("shelter_id")
	targetEmail := r.URL.Query().Get("email")
	if targetEmail == "" {
		d.Log.Debug("Target email is a required parameter")
		BasicHTTPError(w, http.StatusUnprocessableEntity)
		return
	}

	d.Log.Debug("Getting shelter by id.", "shelter_id", shelterID)
	shelter, err := d.ShelterGetter.GetShelterByID(r.Context(), shelterID)
	if err != nil {
		if errors.Is(err, ErrNoShelter) {
			d.Log.Debug("No shelter found with the given id", "shelter_id", shelterID)
			d.NotFoundHandler.ServeHTTP(w, r)
			return
		}

		d.Log.Error("Unexpected error while getting shelter by id.", "shelter_id", shelter.ID)
		BasicHTTPError(w, http.StatusInternalServerError)
		return
	}

	d.Log.Debug("Getting shelter role associated by user.", "shelter_id", shelterID, "user_id", sessionUser.UserID)
	role, err := d.ShelterRoleStore.GetShelterRoleByID(r.Context(), shelter.ID, sessionUser.UserID)
	if err != nil {
		if errors.Is(err, ErrNoShelterRole) {
			d.Log.Debug("No shelter role was found associated with this user.", "user_id", sessionUser.UserID, "shelter_id", shelterID)
			BasicHTTPError(w, http.StatusUnauthorized)
			return
		}

		d.Log.Error("Unexpected error while getting shelter role by id.", "user_id", sessionUser.UserID, "shelter_id", shelter.ID)
		BasicHTTPError(w, http.StatusInternalServerError)
		return
	}

	if role != ShelterRoleAdmin && role != ShelterRoleSuperAdmin {
		d.Log.Error("Unauthorized. Must be an admin or higher", "user_id", sessionUser.UserID, "shelter_id", shelter.ID, "role", role)
		BasicHTTPError(w, http.StatusUnauthorized)
		return
	}

	form := NewShelterRemoveRoleForm()
	form.Confirmation = r.FormValue("confirmation")
	form.Check(form.Confirmation == "", "confirmation", "Please fill out this field.")
	form.Check(form.Confirmation != targetEmail, "confirmation", "Value is invalid.")

	if !form.Valid() {
		d.RenderPage(w, ShelterRemoveRolePage{
			BasePage: BasePage{
				SessionUser: sessionUser,
			},
			ShelterID:   shelter.ID,
			ShelterName: shelter.Name,
			Email:       targetEmail,
			Form:        form,
		})
		return
	}

	role, err = d.ShelterRoleStore.GetShelterRoleByEmail(r.Context(), shelter.ID, targetEmail)
	if err != nil {
		if errors.Is(err, ErrNoUser) {
			d.Log.Debug("Target user doesn't exists", "shelter_id", shelter.ID, "user_id", sessionUser.UserID, "target_email", targetEmail)

			flash := NewFlash("User doesn't exist.", FlashLevelWarn)
			d.SessionManager.Put(r.Context(), SessionKeyFlash, flash)

			redirectURL := strings.ReplaceAll(d.SuccessRedirect, "{shelter_id}", shelterID)
			http.Redirect(w, r, redirectURL, http.StatusSeeOther)
			return
		}

		if errors.Is(err, ErrNoShelterRole) {
			d.Log.Debug("User has no assigned role at the shelter.", "shelter_id", shelter.ID, "user_id", sessionUser.UserID, "target_email", targetEmail)

			flash := NewFlash("User has no assigned role at the shelter.", FlashLevelWarn)
			d.SessionManager.Put(r.Context(), SessionKeyFlash, flash)

			redirectURL := strings.ReplaceAll(d.SuccessRedirect, "{shelter_id}", shelterID)
			http.Redirect(w, r, redirectURL, http.StatusSeeOther)
			return
		}

		d.Log.Error("Unexpected error occurred while getting target's shelter role.", "shelter_id", shelter.ID, "user_id", sessionUser.UserID, "target_email", targetEmail, "reason", err.Error())

		flash := NewFlash("Something went wrong. Please try again later.", FlashLevelError)
		d.RenderPage(w, ShelterRemoveRolePage{
			BasePage: BasePage{
				SessionUser: sessionUser,
			},
			ShelterID:   shelter.ID,
			ShelterName: shelter.Name,
			Email:       targetEmail,
			Flash:       flash,
			Form:        form,
		})
		return
	}

	if role == ShelterRoleSuperAdmin {
		d.Log.Debug("Super admin shelter role is not allowed to be removed this way.")

		flash := NewFlash("Super Admin are not allowed to be removed this way.", FlashLevelError)
		d.SessionManager.Put(r.Context(), SessionKeyFlash, flash)

		redirectURL := strings.ReplaceAll(d.SuccessRedirect, "{shelter_id}", shelterID)
		http.Redirect(w, r, redirectURL, http.StatusSeeOther)
		return
	}

	err = d.ShelterRoleDeleter.DeleteShelterRole(r.Context(), shelter.ID, targetEmail)
	if err != nil {
		d.Log.Error("Unexpected error occurred while deleting shelter role.", "shelter_id", shelter.ID, "user_id", sessionUser.UserID, "target_email", targetEmail, "reason", err.Error())

		flash := NewFlash("Something went wrong. Please try again later.", FlashLevelError)
		d.RenderPage(w, ShelterRemoveRolePage{
			BasePage: BasePage{
				SessionUser: sessionUser,
			},
			ShelterID:   shelter.ID,
			ShelterName: shelter.Name,
			Email:       targetEmail,
			Flash:       flash,
			Form:        form,
		})
		return
	}

	flash := NewFlash("Successfully removed shelter role.", FlashLevelSuccess)
	d.SessionManager.Put(r.Context(), SessionKeyFlash, flash)

	redirectURL := strings.ReplaceAll(d.SuccessRedirect, "{shelter_id}", shelterID)
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

func (d *DoShelterRemoveRoleHandler) RenderPage(w io.Writer, data ShelterRemoveRolePage) {
	err := d.PageTemplateRenderer.RenderPageTemplate(w, "shelter_remove_role.html", data)
	if err != nil {
		panic(err)
	}
}

type ShelterEditRoleHandler struct {
	Log                  *slog.Logger
	PageTemplateRenderer PageTemplateRenderer
	ShelterGetter        ShelterGetter
	ShelterRoleStore     interface {
		ShelterRoleGetter
		ShelterRoleGetterByEmail
	}
	SessionManager  *scs.SessionManager
	NotFoundHandler http.Handler
}

func (s *ShelterEditRoleHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	shelterID := r.PathValue("shelter_id")

	sessionUser := GetSessionUser(r.Context())
	if sessionUser == nil {
		s.Log.Debug("Unauthorized request.")
		RenderClientErrorPage(s.PageTemplateRenderer, w, "Unauthorized request.")
		return
	}

	s.Log.Debug("Getting shelter by id.", "shelter_id", shelterID)
	shelter, err := s.ShelterGetter.GetShelterByID(r.Context(), shelterID)
	if err != nil {
		if errors.Is(err, ErrNoShelter) {
			s.Log.Debug("No shelter found with the given id", "shelter_id", shelterID)
			s.NotFoundHandler.ServeHTTP(w, r)
			return
		}
		s.Log.Error("Unexpected error while getting shelter by id.", "shelter_id", shelter.ID)
		RenderClientErrorPage(s.PageTemplateRenderer, w, "Something went wrong. Please try again later.")
		return
	}

	s.Log.Debug("Getting shelter role associated by user.", "shelter_id", shelterID, "user_id", sessionUser.UserID)
	role, err := s.ShelterRoleStore.GetShelterRoleByID(r.Context(), shelter.ID, sessionUser.UserID)
	if err != nil {
		if errors.Is(err, ErrNoShelterRole) {
			s.Log.Debug("No shelter role was found associated with this user.", "user_id", sessionUser.UserID, "shelter_id", shelterID)
			RenderClientErrorPage(s.PageTemplateRenderer, w, "Unauthorized request.")
			return
		}

		s.Log.Error("Unexpected error while getting shelter role by id.", "user_id", sessionUser.UserID, "shelter_id", shelter.ID)
		RenderClientErrorPage(s.PageTemplateRenderer, w, "Something went wrong. Please try again later.")
		return
	}

	if role != ShelterRoleAdmin && role != ShelterRoleSuperAdmin {
		s.Log.Error("Unauthorized. Must be an admin or higher", "user_id", sessionUser.UserID, "shelter_id", shelter.ID, "role", role)
		s.Error(w, r, "Unauthorized to manage shelter roles. Must be an admin or higher.")
		return
	}

	targetEmail := r.URL.Query().Get("email")
	if targetEmail == "" {
		s.Log.Debug("Target id is a required parameter")
		s.Error(w, r, "Target email is a required parameter.")
		return
	}

	targetRole, err := s.ShelterRoleStore.GetShelterRoleByEmail(r.Context(), shelterID, targetEmail)
	if err != nil {
		s.Log.Error("Unable to query for target's shelter role.", "reason", err.Error())
		s.Error(w, r, "Something went wrong. Please try again later.")
		return
	}

	if targetRole == ShelterRoleSuperAdmin {
		s.Log.Error("Editing super admin's role is not allowed.")
		s.Error(w, r, "Super Admin is not allowed to be edited this way.")
		return
	}

	err = s.PageTemplateRenderer.RenderPageTemplate(w, "shelter_role_edit.html", ShelterRoleEditPage{
		BasePage: BasePage{
			SessionUser: sessionUser,
		},
		ShelterID:   shelterID,
		ShelterName: shelter.Name,
		Email:       targetEmail,
		Role:        string(targetRole),
	})
	if err != nil {
		panic(err)
	}
}

func (d *ShelterEditRoleHandler) Error(w http.ResponseWriter, r *http.Request, message string) {
	flash := NewFlash("Something went wrong. Please try again later.", FlashLevelError)
	d.SessionManager.Put(r.Context(), SessionKeyFlash, flash)
	http.Redirect(w, r, r.Referer(), http.StatusSeeOther)
}

type ShelterRoleEditPage struct {
	BasePage
	Flash       *Flash
	ShelterID   string
	ShelterName string
	Email       string
	Role        string
	RoleError   string
}

type DoShelterEditRoleHandler struct {
	Log                  *slog.Logger
	PageTemplateRenderer PageTemplateRenderer
	ShelterGetter        ShelterGetter
	ShelterRoleStore     interface {
		ShelterRoleGetter
		ShelterRoleGetterByEmail
		ShelterRoleUpdater
	}
	SessionManager     *scs.SessionManager
	NotFoundHandler    http.Handler
	SuccessRedirectURL string
}

type ShelterRoleUpdater interface {
	UpdateShelterRole(ctx context.Context, shelterID, userID string, newRole ShelterRole) error
}

func (d *DoShelterEditRoleHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	shelterID := r.PathValue("shelter_id")

	sessionUser := GetSessionUser(r.Context())
	if sessionUser == nil {
		d.Log.Debug("Unauthorized request.")
		RenderClientErrorPage(d.PageTemplateRenderer, w, "Unauthorized request.")
		return
	}

	d.Log.Debug("Getting shelter by id.", "shelter_id", shelterID)
	shelter, err := d.ShelterGetter.GetShelterByID(r.Context(), shelterID)
	if err != nil {
		if errors.Is(err, ErrNoShelter) {
			d.Log.Debug("No shelter found with the given id", "shelter_id", shelterID)
			d.NotFoundHandler.ServeHTTP(w, r)
			return
		}
		d.Log.Error("Unexpected error while getting shelter by id.", "shelter_id", shelter.ID)
		RenderClientErrorPage(d.PageTemplateRenderer, w, "Something went wrong. Please try again later.")
		return
	}

	d.Log.Debug("Getting shelter role associated by user.", "shelter_id", shelterID, "user_id", sessionUser.UserID)
	role, err := d.ShelterRoleStore.GetShelterRoleByID(r.Context(), shelter.ID, sessionUser.UserID)
	if err != nil {
		if errors.Is(err, ErrNoShelterRole) {
			d.Log.Debug("No shelter role was found associated with this user.", "user_id", sessionUser.UserID, "shelter_id", shelterID)
			RenderClientErrorPage(d.PageTemplateRenderer, w, "Unauthorized request.")
			return
		}

		d.Log.Error("Unexpected error while getting shelter role by id.", "user_id", sessionUser.UserID, "shelter_id", shelter.ID)
		RenderClientErrorPage(d.PageTemplateRenderer, w, "Something went wrong. Please try again later.")
		return
	}

	targetEmail := r.URL.Query().Get("email")
	if targetEmail == "" {
		d.Log.Debug("Target id is a required parameter")
		RenderShelterRoleEditPage(d.PageTemplateRenderer, w, ShelterRoleEditPage{
			BasePage: BasePage{
				SessionUser: sessionUser,
			},
			Flash:       NewFlash("Email is required.", FlashLevelError),
			ShelterID:   shelter.ID,
			ShelterName: shelter.Name,
			Email:       targetEmail,
		})
		return
	}

	if role != ShelterRoleAdmin && role != ShelterRoleSuperAdmin {
		d.Log.Error("Unauthorized. Must be an admin or higher", "user_id", sessionUser.UserID, "shelter_id", shelter.ID, "role", role)
		RenderShelterRoleEditPage(d.PageTemplateRenderer, w, ShelterRoleEditPage{
			BasePage: BasePage{
				SessionUser: sessionUser,
			},
			Flash:       NewFlash("Unauthorized.", FlashLevelError),
			ShelterID:   shelter.ID,
			ShelterName: shelter.Name,
			Email:       targetEmail,
		})
		return
	}

	targetRole, err := d.ShelterRoleStore.GetShelterRoleByEmail(r.Context(), shelterID, targetEmail)
	if err != nil {
		d.Log.Error("Unable to query for target's shelter role.", "reason", err.Error())
		RenderShelterRoleEditPage(d.PageTemplateRenderer, w, ShelterRoleEditPage{
			BasePage: BasePage{
				SessionUser: sessionUser,
			},
			Flash:       NewFlash("Something went wrong. Please try again later.", FlashLevelError),
			ShelterID:   shelter.ID,
			ShelterName: shelter.Name,
			Email:       targetEmail,
		})
		return
	}

	if targetRole == ShelterRoleSuperAdmin {
		d.Log.Error("Editing super admin's role is not allowed.")
		RenderShelterRoleEditPage(d.PageTemplateRenderer, w, ShelterRoleEditPage{
			BasePage: BasePage{
				SessionUser: sessionUser,
			},
			Flash:       NewFlash("Super Admin is not allowed to be edited this way.", FlashLevelError),
			ShelterID:   shelter.ID,
			ShelterName: shelter.Name,
			Email:       targetEmail,
		})
		return
	}

	newRole := r.FormValue("role")
	if !IsValidShelterRole(newRole) {
		d.Log.Debug("Invalid role value.", "role", newRole)
		err := d.PageTemplateRenderer.RenderPageTemplate(w, "shelter_role_edit.html", ShelterRoleEditPage{
			BasePage: BasePage{
				SessionUser: sessionUser,
			},
			ShelterID:   shelterID,
			ShelterName: shelter.Name,
			Email:       targetEmail,
			Role:        newRole,
			RoleError:   "Invalid role value.",
		})
		if err != nil {
			panic("unable to render shelter_edit_role.html template: " + err.Error())
		}
		return
	}

	d.Log.Debug("Updating shelter role.", "shelter_id", shelterID, "user_id", sessionUser.UserID, "target_email", targetEmail)
	err = d.ShelterRoleStore.UpdateShelterRole(r.Context(), shelterID, targetEmail, ShelterRole(newRole))
	if err != nil {
		d.Log.Error("Unexpected error while updating shelter role.", "shelter_id", shelterID, "user_id", sessionUser.UserID, "target_email", targetEmail, "reason", err.Error())
		RenderShelterRoleEditPage(d.PageTemplateRenderer, w, ShelterRoleEditPage{
			BasePage: BasePage{
				SessionUser: sessionUser,
			},
			Flash:       NewFlash("Something went wrong. Please try again later.", FlashLevelError),
			ShelterID:   shelter.ID,
			ShelterName: shelter.Name,
			Email:       targetEmail,
			Role:        newRole,
		})
		return
	}

	d.Log.Info("Successfully updated shelter role.", "shelter_id", shelterID, "user_id", sessionUser.UserID, "target_email", targetEmail)
	flash := NewFlash("Successfully updated shelter role.", FlashLevelSuccess)
	d.SessionManager.Put(r.Context(), SessionKeyFlash, flash)

	redirectURL := strings.ReplaceAll(d.SuccessRedirectURL, "{shelter_id}", shelterID)
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

type ClientErrorPage struct {
	BasePage
	Message string
}

func RenderShelterRoleEditPage(p PageTemplateRenderer, w http.ResponseWriter, data ShelterRoleEditPage) {
	err := p.RenderPageTemplate(w, "shelter_role_edit.html", data)
	if err != nil {
		panic(err)
	}
}

func RenderClientErrorPage(p PageTemplateRenderer, w http.ResponseWriter, message string) {
	err := p.RenderPageTemplate(w, "error.html", ClientErrorPage{
		Message: message,
	})
	if err != nil {
		panic(err)
	}
}

func IsValidShelterRole(role string) bool {
	return role == string(ShelterRoleAdmin) || role == string(ShelterRoleEditor) || role == string(ShelterRoleSuperAdmin)
}
