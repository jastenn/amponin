package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html/template"
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
	UnauthorizedRedirectURL string
}

type ShelterWithRole struct {
	Role ShelterRole
	Shelter
}

func (s *ShelterHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	flash, _ := PopSessionFlash(s.SessionManager, r.Context())
	userSession, _ := GetSessionUser(s.SessionManager, r.Context())
	if userSession == nil {
		http.Redirect(w, r, s.UnauthorizedRedirectURL, http.StatusSeeOther)
		return
	}

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

var ErrNoShelter = errors.New("no shelter found")

type ShelterGetter interface {
	GetShelterByID(ctx context.Context, shelterID string) (*Shelter, error)
}

var ErrNoShelterRole = errors.New("no shelter role found")

type ShelterRoleGetter interface {
	GetShelterRoleByID(ctx context.Context, shelterID, userID string) (ShelterRole, error)
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

type ShelterUpdateHandler struct {
	Log                  *slog.Logger
	PageTemplateRenderer PageTemplateRenderer
	SessionManager       *scs.SessionManager
	NotFoundHandler      http.Handler
	ShelterGetter        ShelterGetter
	ShelterRoleGetter    ShelterRoleGetter
	LoginRedirectURL     string
	ErrorRedirectURL     string
}

func (s *ShelterUpdateHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	allowedRoles := []ShelterRole{ShelterRoleAdmin, ShelterRoleSuperAdmin, ShelterRoleEditor}

	shelterID := r.PathValue("shelter_id")
	sessionUser, _ := GetSessionUser(s.SessionManager, r.Context())
	if sessionUser == nil {
		redirectURL := strings.ReplaceAll(s.LoginRedirectURL, "{shelter_id}", shelterID)
		http.Redirect(w, r, redirectURL, http.StatusSeeOther)
		return
	}

	role, err := s.ShelterRoleGetter.GetShelterRoleByID(r.Context(), shelterID, sessionUser.UserID)
	if err != nil {
		if errors.Is(err, ErrNoShelterRole) {
			s.Log.Debug(
				"No shelter role was found associated with this user.",
				"user_id", sessionUser.UserID,
				"shelter_id", shelterID,
			)
			s.NotFoundHandler.ServeHTTP(w, r)
			return
		}

		s.Log.Error(
			"Unexpected error while getting shelter role associated to user.",
			"user_id", sessionUser.UserID,
			"shelter_id", shelterID,
		)
		http.Redirect(w, r, s.ErrorRedirectURL, http.StatusSeeOther)
		return
	}

	if !slices.Contains(allowedRoles, role) {
		s.Log.Debug("User's role is not allowed to take this action", "role", role)
		BasicHTTPError(w, http.StatusUnauthorized)
		return
	}

	shelter, err := s.ShelterGetter.GetShelterByID(r.Context(), shelterID)
	if err != nil {
		s.Log.Error(
			"Unexpected error while shelter with id.",
			"shelter_id", shelterID,
		)
		http.Redirect(w, r, s.ErrorRedirectURL, http.StatusSeeOther)
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
	LoginRedirectURL   string
	ErrorRedirectURL   string
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
	allowedRoles := []ShelterRole{ShelterRoleAdmin, ShelterRoleSuperAdmin, ShelterRoleEditor}

	shelterID := r.PathValue("shelter_id")
	sessionUser, _ := GetSessionUser(d.SessionManager, r.Context())
	if sessionUser == nil {
		redirectURL := strings.ReplaceAll(d.LoginRedirectURL, "{shelter_id}", shelterID)
		http.Redirect(w, r, redirectURL, http.StatusSeeOther)
		return
	}

	role, err := d.ShelterRoleGetter.GetShelterRoleByID(r.Context(), shelterID, sessionUser.UserID)
	if err != nil {
		if errors.Is(err, ErrNoShelterRole) {
			d.Log.Debug(
				"No shelter role was found associated with this user.",
				"user_id", sessionUser.UserID,
				"shelter_id", shelterID,
			)
			d.NotFoundHandler.ServeHTTP(w, r)
			return
		}

		d.Log.Error(
			"Unexpected error while getting shelter role associated to user.",
			"user_id", sessionUser.UserID,
			"shelter_id", shelterID,
		)
		http.Redirect(w, r, d.ErrorRedirectURL, http.StatusSeeOther)
		return
	}

	if !slices.Contains(allowedRoles, role) {
		d.Log.Debug("User's role is not allowed to take this action", "role", role)
		BasicHTTPError(w, http.StatusUnauthorized)
		return
	}

	shelter, err := d.ShelterGetter.GetShelterByID(r.Context(), shelterID)
	if err != nil {
		d.Log.Error(
			"Unexpected error while shelter with id.",
			"shelter_id", shelterID,
		)
		http.Redirect(w, r, d.ErrorRedirectURL, http.StatusSeeOther)
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
		Coordinates: coordinates,
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
	SessionManager          *scs.SessionManager
	UnauthorizedRedirectURL string
	NotFoundHandler         http.Handler
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
	sessionUser, _ := GetSessionUser(s.SessionManager, r.Context())
	if sessionUser == nil {
		s.Log.Debug("Unauthorized access received. Redirecting user.")
		http.Redirect(w, r, s.UnauthorizedRedirectURL, http.StatusSeeOther)
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
			s.Log.Debug(
				"No shelter role was found associated with this user.",
				"user_id", sessionUser.UserID,
				"shelter_id", shelterID,
			)
			s.NotFoundHandler.ServeHTTP(w, r)
			return
		}

		s.Log.Error(
			"Unexpected error while getting shelter role associated to user.",
			"user_id", sessionUser.UserID,
			"shelter_id", shelterID,
		)
		s.RenderPage(w, ShelterRolesPage{
			BasePage: BasePage{
				SessionUser: sessionUser,
			},
			Flash:       NewFlash("Something went wrong. Please try again later.", FlashLevelError),
			ShelterID:   shelter.ID,
			ShelterName: shelter.Name,
		})
		return
	}

	shelterRoles, err := s.ShelterRolesFinder.FindShelterRoles(r.Context(), shelter.ID)
	if err != nil {
		s.Log.Error("Unexpected error while getting shelter roles by id", "shelter_id", shelterID, "reason", err.Error())
		s.RenderPage(w, ShelterRolesPage{
			BasePage: BasePage{
				SessionUser: sessionUser,
			},
			Role:        role,
			ShelterID:   shelter.ID,
			ShelterName: shelter.Name,
			Flash:       NewFlash("Something went wrong. Please try again later.", FlashLevelError),
		})
		return
	}

	s.Log.Debug("Successfully find shelter roles by id.", "roles_count", len(shelterRoles))
	s.RenderPage(w, ShelterRolesPage{
		BasePage: BasePage{
			SessionUser: sessionUser,
		},
		Role:         role,
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
	Role         ShelterRole
	ShelterID    string
	ShelterName  string
	ShelterRoles []*FindShelterRolesResult
}
