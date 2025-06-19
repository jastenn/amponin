package main

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/mail"
	"slices"
	"strconv"
	"strings"
	"time"
)

var ErrNoShelter = errors.New("no shelter found")

type ShelterRole string

func (s ShelterRole) String() string {
	switch s {
	case ShelterRoleSuperAdmin:
		return "Super Admin"
	case ShelterRoleAdmin:
		return "Admin"
	case ShelterRoleEditor:
		return "Editor"
	case ShelterNoRole:
		return ""
	default:
		panic("invalid shelter role")
	}
}

const (
	ShelterNoRole         ShelterRole = ""
	ShelterRoleSuperAdmin ShelterRole = "super_admin"
	ShelterRoleAdmin      ShelterRole = "admin"
	ShelterRoleEditor     ShelterRole = "editor"
)

var ErrNoShelterRole = errors.New("no shelter role found.")

type shelterRoleGetter interface {
	GetShelterRole(ctx context.Context, shelterID, userID string) (ShelterRole, error)
}

type Shelter struct {
	ID          string
	Name        string
	Address     string
	Avatar      *Image
	Coordinates Coordinates
	Description string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type Coordinates struct {
	Latitude float64
	Longtude float64
}

func (c Coordinates) String() string {
	return fmt.Sprintf("%v %v", c.Latitude, c.Longtude)
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
	// SuccessRedirectURL is a url when registration is successful.
	// Pattern {shelter_id} is substitude
	SuccessRedirectURL string
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
	FieldValues shelterFormValues
	FieldErrors shelterFormErrors
}

type shelterFormValues struct {
	Name        string
	Avatar      *multipart.FileHeader
	Address     string
	Coordinates string
	Description string
}

type shelterFormErrors struct {
	Name        string
	Avatar      string
	Address     string
	Coordinates string
	Description string
}

func validateShelterFormValues(fieldValues shelterFormValues) (valid bool, fieldErrors shelterFormErrors) {
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

	valid = fieldErrors.Name == "" &&
		fieldErrors.Avatar == "" &&
		fieldErrors.Address == "" &&
		fieldErrors.Coordinates == "" &&
		fieldErrors.Description == ""

	return valid, fieldErrors

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
		fieldValues := shelterFormValues{
			Name:        r.FormValue("name"),
			Address:     r.FormValue("address"),
			Coordinates: r.FormValue("coordinates"),
			Description: r.FormValue("description"),
		}

		valid, fieldErrors := validateShelterFormValues(fieldValues)
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
				Flash:       newFlash(flashLevelError, clientMessageUnexpectedError),
				FieldValues: fieldValues,
			})
			return
		}

		rh.Log.Info("New shelter was created.", "shelter_id", shelter.ID, "user_id", loginSessionData.UserID)

		redirectURL := strings.ReplaceAll(rh.SuccessRedirectURL, "{shelter_id}", shelter.ID)
		setFlash(w, flashLevelSuccess, "Successfully registered a new shelter.")
		http.Redirect(w, r, redirectURL, http.StatusSeeOther)
		return
	}

	rh.renderPage(w, http.StatusOK, registerShelterPageData{
		basePageData: basePageData{
			LoginSession: loginSessionData,
		},
		Flash: nil,
	})
}

func (rh *RegisterShelterHandler) renderPage(w http.ResponseWriter, status int, data registerShelterPageData) {
	err := RenderPage(w, registerShelterPage, status, data)
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

type GetShelterByIDHandler struct {
	Log               *slog.Logger
	SessionStore      *CookieSessionStore
	ShelterGetterByID shelterGetter
	ShelterRoleGetter shelterRoleGetter
	NotFoundHandler   http.Handler
}

type shelterGetter interface {
	GetShelterByID(ctx context.Context, id string) (*Shelter, error)
}

type shelterByIDPageData struct {
	basePageData
	Flash *flash
	Role  ShelterRole
	Shelter
}

var getShelterByIDPage = template.Must(template.ParseFS(embedFS, "templates/pages/shelter/get_by_id.html", "templates/pages/base.html"))

func (g *GetShelterByIDHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var loginSessionData *loginSession
	g.SessionStore.Decode(r, sessionKeyLoginSession, &loginSessionData)

	shelterID := r.PathValue("shelter_id")

	shelter, err := g.ShelterGetterByID.GetShelterByID(r.Context(), shelterID)
	if err != nil {
		if errors.Is(err, ErrNoShelter) {
			g.Log.Info("Shelter not found.", "shelter_id", shelterID)
			g.NotFoundHandler.ServeHTTP(w, r)
			return
		}

		renderErrorPage(w, errorPageData{
			basePageData: basePageData{
				LoginSession: loginSessionData,
			},
			Status:  http.StatusInternalServerError,
			Message: clientMessageUnexpectedError,
		})
		g.Log.Error("Unexpected error while getting shelter by id.", "error", err.Error())
		return
	}

	var role ShelterRole
	if loginSessionData != nil {
		role, err = g.ShelterRoleGetter.GetShelterRole(r.Context(), shelterID, loginSessionData.UserID)
		if err != nil && !errors.Is(err, ErrNoShelterRole) {
			g.Log.Error(
				"Unexpected error while getting shelter role.",
				"shelter_id", shelterID,
				"user_id", loginSessionData.UserID,
			)
			renderErrorPage(w, errorPageData{
				basePageData: basePageData{
					LoginSession: loginSessionData,
				},
				Status:  http.StatusInternalServerError,
				Message: clientMessageUnexpectedError,
			})
			return
		}
	}

	flash := getFlash(w, r)
	err = RenderPage(w, getShelterByIDPage, http.StatusOK, shelterByIDPageData{
		basePageData: basePageData{
			LoginSession: loginSessionData,
		},
		Role:    role,
		Flash:   flash,
		Shelter: *shelter,
	})
	if err != nil {
		g.Log.Error("Unexpected error while rendering page.", "error", err.Error())
		renderErrorPage(w, errorPageData{
			basePageData: basePageData{
				LoginSession: loginSessionData,
			},
			Status:  http.StatusInternalServerError,
			Message: clientMessageUnexpectedError,
		})
		return
	}
	return
}

type ListManagedShelterHandler struct {
	Log                  *slog.Logger
	SessionStore         *CookieSessionStore
	ManagedShelterFinder managedShelterFinder
}

type ManagedShelterResult struct {
	Role ShelterRole
	*Shelter
}

type managedShelterFinder interface {
	FindManagedShelter(ctx context.Context, userID string) ([]*ManagedShelterResult, error)
}

type listManagedShelterPageData struct {
	basePageData
	Shelters []*ManagedShelterResult
}

var listManagedShelterPage = template.Must(template.ParseFS(embedFS, "templates/pages/shelter/list_managed.html", "templates/pages/base.html"))

func (l *ListManagedShelterHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var loginSessionData *loginSession
	l.SessionStore.Decode(r, sessionKeyLoginSession, &loginSessionData)

	if loginSessionData == nil {
		l.Log.Debug("User is not logged in.")
		renderErrorPage(w, errorPageData{
			Status:  http.StatusUnauthorized,
			Message: "Unauthorized. Please login first.",
		})
		return
	}

	result, err := l.ManagedShelterFinder.FindManagedShelter(r.Context(), loginSessionData.UserID)
	if err != nil {
		l.Log.Error("Unexpected error while finding shelter.", "error", err.Error())
		renderErrorPage(w, errorPageData{
			basePageData: basePageData{
				LoginSession: loginSessionData,
			},
			Status:  http.StatusInternalServerError,
			Message: clientMessageUnexpectedError,
		})
		return
	}

	err = RenderPage(w, listManagedShelterPage, http.StatusOK, listManagedShelterPageData{
		basePageData: basePageData{
			LoginSession: loginSessionData,
		},
		Shelters: result,
	})
	if err != nil {
		l.Log.Error("Unable to render page.", "error", err.Error())
		renderErrorPage(w, errorPageData{
			basePageData: basePageData{
				LoginSession: loginSessionData,
			},
			Status:  http.StatusInternalServerError,
			Message: clientMessageUnexpectedError,
		})
		return
	}
}

type ShelterSettingsHandler struct {
	Log             *slog.Logger
	SessionStore    *CookieSessionStore
	NotFoundHandler http.Handler
	ShelterGetter   shelterGetterWithRole
}

type shelterGetterWithRole interface {
	GetShelterWithRole(ctx context.Context, shelterID, userID string) (*Shelter, ShelterRole, error)
}

type shelterSettingsPageData struct {
	basePageData
	ShelterName string
	ShelterID   string
	Role        ShelterRole
}

var shelterSettingsPage = template.Must(template.ParseFS(embedFS, "templates/pages/shelter/settings.html", "templates/pages/base.html"))

func (s *ShelterSettingsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var loginSessionData *loginSession
	s.SessionStore.Decode(r, sessionKeyLoginSession, &loginSessionData)

	shelterID := r.PathValue("shelter_id")

	cfg := shelterRoleGuardConfig{
		store:        s.ShelterGetter,
		log:          s.Log,
		loginSession: loginSessionData,
		shelterID:    shelterID,
		allowedRoles: []ShelterRole{ShelterRoleSuperAdmin, ShelterRoleAdmin, ShelterRoleEditor},
	}
	shelter, role, shouldReturn := shelterRoleGuard(r.Context(), w, cfg)
	if shouldReturn {
		return
	}

	err := RenderPage(w, shelterSettingsPage, http.StatusOK, shelterSettingsPageData{
		basePageData: basePageData{
			LoginSession: loginSessionData,
		},
		ShelterName: shelter.Name,
		ShelterID:   shelter.ID,
		Role:        role,
	})
	if err != nil {
		s.Log.Error("Unable to render page.", "error", err.Error())
		renderErrorPage(w, errorPageData{
			basePageData: basePageData{
				LoginSession: loginSessionData,
			},
			Status:  http.StatusInternalServerError,
			Message: clientMessageUnexpectedError,
		})
		return
	}
}

type ShelterUpdateInfoHandler struct {
	Log             *slog.Logger
	SessionStore    *CookieSessionStore
	NotFoundHandler http.Handler
	ImageStore      *LocalImageStore
	ShelterStore    interface {
		shelterGetterWithRole
		shelterUpdater
	}
	SuccessRedirectURL string
}

type shelterUpdater interface {
	UpdateShelter(ctx context.Context, shelterID string, data UpdateShelterData) (*Shelter, error)
}

type UpdateShelterData struct {
	Name        *string
	Avatar      *Image
	Address     *string
	Coordinates *Coordinates
	Description *string
}

type shelterUpdateInfoPageData struct {
	basePageData
	Shelter     *Shelter
	FieldValues shelterFormValues
	FieldErrors shelterFormErrors
	Flash       *flash
}

var shelterUpdateInfoPage = template.Must(template.ParseFS(embedFS, "templates/pages/shelter/update_info.html", "templates/pages/base.html"))

func (e *ShelterUpdateInfoHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var loginSessionData *loginSession
	e.SessionStore.Decode(r, sessionKeyLoginSession, &loginSessionData)

	shelterID := r.PathValue("shelter_id")

	cfg := shelterRoleGuardConfig{
		store:        e.ShelterStore,
		log:          e.Log,
		loginSession: loginSessionData,
		shelterID:    shelterID,
		allowedRoles: []ShelterRole{ShelterRoleSuperAdmin, ShelterRoleAdmin, ShelterRoleEditor},
	}
	shelter, _, shouldReturn := shelterRoleGuard(r.Context(), w, cfg)
	if shouldReturn {
		return
	}

	if r.Method == http.MethodPost {
		err := r.ParseMultipartForm(10_000_000)
		if err != nil {
			e.Log.Error("Unable to parse form as multipart", "error", err.Error())
			e.renderPage(w, http.StatusInternalServerError, shelterUpdateInfoPageData{
				basePageData: basePageData{
					LoginSession: loginSessionData,
				},
				Shelter: shelter,
				Flash:   newFlash(flashLevelError, clientMessageUnexpectedError),
			})
			return
		}

		fieldValues := shelterFormValues{
			Name:        r.FormValue("name"),
			Address:     r.FormValue("address"),
			Coordinates: r.FormValue("coordinates"),
			Description: r.FormValue("description"),
		}

		_, fieldValues.Avatar, err = r.FormFile("avatar")
		if err != nil && !errors.Is(err, http.ErrMissingFile) {
			e.Log.Error("Unable to parse avatar field.", "error", err.Error())
			e.renderPage(w, http.StatusInternalServerError, shelterUpdateInfoPageData{
				basePageData: basePageData{
					LoginSession: loginSessionData,
				},
				Shelter:     shelter,
				FieldValues: fieldValues,
				Flash:       newFlash(flashLevelError, clientMessageUnexpectedError),
			})
			return
		}

		valid, fieldErrors := validateShelterFormValues(fieldValues)
		if !valid {
			e.Log.Debug("Field values validation failed.", "field_values", fieldValues, "field_errors", fieldErrors)
			e.renderPage(w, http.StatusUnprocessableEntity, shelterUpdateInfoPageData{
				basePageData: basePageData{
					LoginSession: loginSessionData,
				},
				Shelter:     shelter,
				FieldValues: fieldValues,
				FieldErrors: fieldErrors,
			})
			return
		}

		var avatar *Image
		if fieldValues.Avatar != nil {
			var err error
			avatar, err = e.ImageStore.Store(fieldValues.Avatar)
			if err != nil {
				e.Log.Debug("Unable to store avatar.", "error", err.Error())
				fieldErrors.Avatar = "Unable to upload avatar."
				e.renderPage(w, http.StatusInternalServerError, shelterUpdateInfoPageData{
					basePageData: basePageData{
						LoginSession: loginSessionData,
					},
					FieldErrors: fieldErrors,
				})
				return
			}
		}

		coordinates, err := ParseCoordinates(fieldValues.Coordinates)
		if err != nil {
			panic(fmt.Errorf("unable to parse coordinates: %w", err))
		}

		_, err = e.ShelterStore.UpdateShelter(r.Context(), shelterID, UpdateShelterData{
			Name:        &fieldValues.Name,
			Avatar:      avatar,
			Address:     &fieldValues.Address,
			Coordinates: coordinates,
			Description: &fieldValues.Description,
		})
		if err != nil {
			e.Log.Error("Unable to update shelter.", "error", err.Error(), "shelter_id", shelterID)
			e.renderPage(w, http.StatusInternalServerError, shelterUpdateInfoPageData{
				basePageData: basePageData{
					LoginSession: loginSessionData,
				},
				Shelter:     shelter,
				FieldValues: fieldValues,
				Flash:       newFlash(flashLevelError, clientMessageUnexpectedError),
			})
			return
		}

		e.Log.Info("Shelter info updated.", "shelter_id", shelterID, "user_id", loginSessionData.UserID)

		redirectURL := strings.ReplaceAll(e.SuccessRedirectURL, "{shelter_id}", shelterID)
		setFlash(w, flashLevelSuccess, "Shelter info was updated successfully.")
		http.Redirect(w, r, redirectURL, http.StatusSeeOther)
		return
	}

	e.renderPage(w, http.StatusOK, shelterUpdateInfoPageData{
		basePageData: basePageData{
			LoginSession: loginSessionData,
		},
		Shelter: shelter,
		FieldValues: shelterFormValues{
			Name:        shelter.Name,
			Address:     shelter.Address,
			Coordinates: shelter.Coordinates.String(),
			Description: shelter.Description,
		},
	})
}

func (e ShelterUpdateInfoHandler) renderPage(w http.ResponseWriter, status int, data shelterUpdateInfoPageData) {
	err := RenderPage(w, shelterUpdateInfoPage, status, data)
	if err != nil {
		e.Log.Error("Unable to render page.", "error", err.Error())
		renderErrorPage(w, errorPageData{
			basePageData: data.basePageData,
			Status:       http.StatusInternalServerError,
			Message:      clientMessageUnexpectedError,
		})
		return
	}
}

type ShelterRolesHandler struct {
	Log          *slog.Logger
	SessionStore *CookieSessionStore
	ShelterStore interface {
		shelterRolesFinder
		shelterGetterWithRole
	}
}

type shelterRolesFinder interface {
	FindShelterRoles(ctx context.Context, shelterID string) ([]ShelterRoleFindResult, error)
}

type ShelterRoleFindResult struct {
	Role ShelterRole
	User *User
}

type shelterRolesPageData struct {
	basePageData
	Flash    *flash
	UserRole ShelterRole
	Shelter  *Shelter
	Roles    []ShelterRoleFindResult
}

var shelterRolesPage = template.Must(template.ParseFS(embedFS, "templates/pages/shelter/roles.html", "templates/pages/base.html"))

func (s *ShelterRolesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var loginSessionData *loginSession
	s.SessionStore.Decode(r, sessionKeyLoginSession, &loginSessionData)

	shelterID := r.PathValue("shelter_id")

	cfg := shelterRoleGuardConfig{
		store:        s.ShelterStore,
		log:          s.Log,
		loginSession: loginSessionData,
		shelterID:    shelterID,
		allowedRoles: []ShelterRole{ShelterRoleAdmin, ShelterRoleSuperAdmin},
	}
	shelter, role, shouldReturn := shelterRoleGuard(r.Context(), w, cfg)
	if shouldReturn {
		return
	}

	roles, err := s.ShelterStore.FindShelterRoles(r.Context(), shelterID)
	if err != nil {
		s.Log.Error("Unable to query for shelter with related roles.", "error", err.Error(), "shelter_id", shelterID)
		renderErrorPage(w, errorPageData{
			basePageData: basePageData{
				LoginSession: loginSessionData,
			},
			Status:  http.StatusInternalServerError,
			Message: clientMessageUnexpectedError,
		})
		return
	}

	flash := getFlash(w, r)
	err = RenderPage(w, shelterRolesPage, http.StatusOK, shelterRolesPageData{
		basePageData: basePageData{
			LoginSession: loginSessionData,
		},
		UserRole: role,
		Flash:    flash,
		Shelter:  shelter,
		Roles:    roles,
	})
	if err != nil {
		s.Log.Error("Unable to render page.", "error", err.Error())
		renderErrorPage(w, errorPageData{
			basePageData: basePageData{
				LoginSession: loginSessionData,
			},
			Status:  http.StatusInternalServerError,
			Message: clientMessageUnexpectedError,
		})
		return
	}
}

type ShelterAddRoleHandler struct {
	Log          *slog.Logger
	SessionStore *CookieSessionStore
	ShelterStore interface {
		shelterGetterWithRole
		shelterRoleRegistryWithEmail
	}
	SuccessRedirectURL string
}

var ErrDuplicateShelterRoleUser = errors.New("user already have a role in shelter")

type shelterRoleRegistryWithEmail interface {
	RegisterShelterRoleWithEmail(ctx context.Context, userEmail string, shelterID string, role ShelterRole) error
}

type shelterAddRolePageData struct {
	basePageData
	Flash       *flash
	Shelter     *Shelter
	UserRole    ShelterRole
	FieldValues shelterAddRoleValues
	FieldErrors shelterAddRoleErrors
}

type shelterAddRoleValues struct {
	Email string
	Role  ShelterRole
}

type shelterAddRoleErrors struct {
	Email string
	Role  ShelterRole
}

func validateShelterAddRoleValues(userRole ShelterRole, fieldValues shelterAddRoleValues) (valid bool, fieldErrors shelterAddRoleErrors) {
	if fieldValues.Email == "" {
		fieldErrors.Email = "Please fill out this field."
	} else if _, err := mail.ParseAddress(fieldValues.Email); err != nil {
		fieldErrors.Email = "Email is invalid."
	}

	validRoles := []ShelterRole{ShelterRoleSuperAdmin, ShelterRoleAdmin, ShelterRoleEditor}
	if fieldValues.Role == "" {
		fieldErrors.Role = "Please fill out this field."
	} else if !slices.Contains(validRoles, fieldValues.Role) {
		fieldErrors.Role = "Role is invalid."
	} else if userRole != ShelterRoleSuperAdmin && fieldValues.Role == ShelterRoleAdmin {
		fieldErrors.Role = "You are not allowed to assign admin role."
	}

	valid = fieldErrors.Email == "" && fieldErrors.Role == ""
	return valid, fieldErrors
}

var shelterAddRolePage = template.Must(template.ParseFS(embedFS, "templates/pages/shelter/add_role.html", "templates/pages/base.html"))

func (s *ShelterAddRoleHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var loginSessionData *loginSession
	s.SessionStore.Decode(r, sessionKeyLoginSession, &loginSessionData)

	shelterID := r.PathValue("shelter_id")

	cfg := shelterRoleGuardConfig{
		store:        s.ShelterStore,
		log:          s.Log,
		loginSession: loginSessionData,
		shelterID:    shelterID,
		allowedRoles: []ShelterRole{ShelterRoleAdmin, ShelterRoleSuperAdmin},
	}
	shelter, role, shouldReturn := shelterRoleGuard(r.Context(), w, cfg)
	if shouldReturn {
		return
	}

	if r.Method == http.MethodPost {
		fieldValues := shelterAddRoleValues{
			Email: r.FormValue("email"),
			Role:  ShelterRole(r.FormValue("role")),
		}

		valid, fieldErrors := validateShelterAddRoleValues(role, fieldValues)
		if !valid {
			s.Log.Debug("Field validation failed.", "field_errors", fieldErrors, "field_values", fieldValues)
			s.renderPage(w, http.StatusUnprocessableEntity, shelterAddRolePageData{
				basePageData: basePageData{
					LoginSession: loginSessionData,
				},
				UserRole:    role,
				Shelter:     shelter,
				FieldValues: fieldValues,
				FieldErrors: fieldErrors,
			})
			return
		}

		err := s.ShelterStore.RegisterShelterRoleWithEmail(r.Context(), fieldValues.Email, shelterID, fieldValues.Role)
		if err != nil {
			if errors.Is(err, ErrDuplicateShelterRoleUser) {
				s.Log.Debug("User already has a role in this shelter.", "shelter_id", shelter.ID, "user_email", fieldValues.Email)
				flashData := newFlash(flashLevelError, "User already has a role in this shelter.")
				s.renderPage(w, http.StatusUnprocessableEntity, shelterAddRolePageData{
					basePageData: basePageData{
						LoginSession: loginSessionData,
					},
					UserRole:    role,
					Flash:       flashData,
					Shelter:     shelter,
					FieldValues: fieldValues,
				})
				return
			}

			if errors.Is(err, ErrNoUser) {
				s.Log.Debug("User with the given email not found.", "shelter_id", shelterID, "user_email", fieldValues.Email)
				message := fmt.Sprintf("User with %v email doesn't exists.", fieldValues.Email)
				flashData := newFlash(flashLevelError, message)
				s.renderPage(w, http.StatusUnprocessableEntity, shelterAddRolePageData{
					basePageData: basePageData{
						LoginSession: loginSessionData,
					},
					UserRole:    role,
					Flash:       flashData,
					Shelter:     shelter,
					FieldValues: fieldValues,
				})
				return
			}

			s.Log.Error("Unable to register shelter role with email.", "error", err.Error(), "shelter_id", shelterID, "user_email", fieldValues.Email)
			s.renderPage(w, http.StatusInternalServerError, shelterAddRolePageData{
				basePageData: basePageData{
					LoginSession: loginSessionData,
				},
				UserRole:    role,
				Shelter:     shelter,
				Flash:       newFlash(flashLevelError, clientMessageUnexpectedError),
				FieldValues: fieldValues,
			})
			return
		}

		s.Log.Info("User has been added and assigned a role", "shelter_id", shelterID, "user_email", fieldValues.Email, "role", fieldValues.Role)

		redirectURL := strings.ReplaceAll(s.SuccessRedirectURL, "{shelter_id}", shelterID)
		message := fmt.Sprintf("Success! %v has been added and assigned the role of %v", fieldValues.Email, fieldValues.Role)
		setFlash(w, flashLevelSuccess, message)
		http.Redirect(w, r, redirectURL, http.StatusSeeOther)
		return
	}

	s.renderPage(w, http.StatusOK, shelterAddRolePageData{
		basePageData: basePageData{
			LoginSession: loginSessionData,
		},
		UserRole: role,
		Shelter:  shelter,
	})
}

func (s *ShelterAddRoleHandler) renderPage(w http.ResponseWriter, status int, data shelterAddRolePageData) {
	err := RenderPage(w, shelterAddRolePage, status, data)
	if err != nil {
		s.Log.Error("Unable to render page.", "error", err.Error())
		renderErrorPage(w, errorPageData{
			basePageData: data.basePageData,
			Status:       http.StatusInternalServerError,
			Message:      clientMessageUnexpectedError,
		})
		return
	}
}

type ShelterRemoveRoleHandler struct {
	Log          *slog.Logger
	SessionStore *CookieSessionStore
	ShelterStore interface {
		shelterGetterWithRole
		shelterRoleGetter
		shelterRoleRemover
	}
	UserStore       userGetter
	ShelterRolesURL string
}

type shelterRoleRemover interface {
	RemoveShelterRole(ctx context.Context, shelterID string, userID string) error
}

type userGetter interface {
	GetUser(ctx context.Context, userID string) (*User, error)
}

type shelterRemoveRolePageData struct {
	basePageData
	Shelter                 *Shelter
	User                    *User
	Role                    ShelterRole
	ConfirmationPhrase      string
	ConfirmationPhraseError string
}

var shelterRemoveRolePage = template.Must(template.ParseFS(embedFS, "templates/pages/shelter/remove_role.html", "templates/pages/base.html"))

func (s *ShelterRemoveRoleHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var loginSessionData *loginSession
	s.SessionStore.Decode(r, sessionKeyLoginSession, &loginSessionData)

	shelterID := r.PathValue("shelter_id")

	cfg := shelterRoleGuardConfig{
		store:        s.ShelterStore,
		log:          s.Log,
		loginSession: loginSessionData,
		shelterID:    shelterID,
		allowedRoles: []ShelterRole{ShelterRoleAdmin, ShelterRoleSuperAdmin},
	}
	shelter, role, shouldReturn := shelterRoleGuard(r.Context(), w, cfg)

	if shouldReturn {
		return
	}

	targetID := r.URL.Query().Get("user-id")
	targetRole, err := s.ShelterStore.GetShelterRole(r.Context(), shelterID, targetID)
	if err != nil {
		if errors.Is(err, ErrNoShelterRole) {
			s.Log.Debug("This user does not have a role assigned to this shelter.", "shelter_id", shelterID, "user_id", targetID)

			flashData := newFlash(flashLevelError, "The user does not have a role assigned to this shelter.")
			s.SessionStore.Encode(w, sessionKeyFlash, flashData, flashMaxAge)

			redirectURL := strings.ReplaceAll(s.ShelterRolesURL, "{shelter_id}", shelter.ID)
			http.Redirect(w, r, redirectURL, http.StatusSeeOther)
			return
		}

		s.Log.Error("Unable to get target user shelter role.", "shelter_id", shelterID, "user_id", targetID)

		flashData := newFlash(flashLevelError, clientMessageUnexpectedError)
		s.SessionStore.Encode(w, sessionKeyFlash, flashData, flashMaxAge)

		redirectURL := strings.ReplaceAll(s.ShelterRolesURL, "{shelter_id}", shelter.ID)
		http.Redirect(w, r, redirectURL, http.StatusSeeOther)
		return
	}

	if targetRole == ShelterRoleSuperAdmin {
		s.Log.Debug("Super admin are not allowed to be removed this way.", "user_role", role, "target_role", targetRole)

		flashData := newFlash(flashLevelError, "Super admin are not allowed to be removed this way.")
		s.SessionStore.Encode(w, sessionKeyFlash, flashData, flashMaxAge)

		redirectURL := strings.ReplaceAll(s.ShelterRolesURL, "{shelter_id}", shelter.ID)
		http.Redirect(w, r, redirectURL, http.StatusSeeOther)
		return
	}

	if targetRole == ShelterRoleAdmin && role == ShelterRoleAdmin {
		s.Log.Debug("User cannot remove a role equivalent to their own.", "user_role", role, "target_role", targetRole)

		flashData := newFlash(flashLevelError, "You cannot remove a role equivalent to your own.")
		s.SessionStore.Encode(w, sessionKeyFlash, flashData, flashMaxAge)

		redirectURL := strings.ReplaceAll(s.ShelterRolesURL, "{shelter_id}", shelter.ID)
		http.Redirect(w, r, redirectURL, http.StatusSeeOther)
		return
	}

	targetUser, err := s.UserStore.GetUser(r.Context(), targetID)
	if err != nil {
		s.Log.Error("Unable to get target user.", "user_id", targetID)

		flashData := newFlash(flashLevelError, clientMessageUnexpectedError)
		s.SessionStore.Encode(w, sessionKeyFlash, flashData, flashMaxAge)

		redirectURL := strings.ReplaceAll(s.ShelterRolesURL, "{shelter_id}", shelter.ID)
		http.Redirect(w, r, redirectURL, http.StatusSeeOther)
		return
	}

	if r.Method == http.MethodPost {
		confirmationPhrase := r.FormValue("confirmation-phrase")
		var confirmationPhraseError string
		if confirmationPhrase == "" {
			confirmationPhraseError = "Please fill out this field."
		} else if confirmationPhrase != "Confirm role removal" {
			confirmationPhraseError = "Confirmation phrase incorrect."
		}

		if confirmationPhraseError != "" {
			s.Log.Debug("Confirmation Phrase validation error", "error", confirmationPhraseError)
			s.renderPage(w, http.StatusUnprocessableEntity, shelterRemoveRolePageData{
				basePageData: basePageData{
					LoginSession: loginSessionData,
				},
				Shelter:                 shelter,
				User:                    targetUser,
				Role:                    targetRole,
				ConfirmationPhrase:      confirmationPhrase,
				ConfirmationPhraseError: confirmationPhraseError,
			})
			return
		}

		err := s.ShelterStore.RemoveShelterRole(r.Context(), shelterID, targetID)
		if err != nil {
			s.Log.Error("Unable to remove shelter role.", "error", err.Error())

			flashData := newFlash(flashLevelError, clientMessageUnexpectedError)
			s.SessionStore.Encode(w, sessionKeyFlash, flashData, flashMaxAge)

			redirectURL := strings.ReplaceAll(s.ShelterRolesURL, "{shelter_id}", shelter.ID)
			http.Redirect(w, r, redirectURL, http.StatusSeeOther)
			return
		}

		s.Log.Info("Shelter role associated with the user removed successfully.", "shelter_id", shelterID, "user_id", targetID)

		message := fmt.Sprintf("Role associated with %v was removed.", targetUser.Email)
		flashData := newFlash(flashLevelSuccess, message)
		s.SessionStore.Encode(w, sessionKeyFlash, flashData, flashMaxAge)

		redirectURL := strings.ReplaceAll(s.ShelterRolesURL, "{shelter_id}", shelter.ID)
		http.Redirect(w, r, redirectURL, http.StatusSeeOther)
		return
	}

	s.renderPage(w, http.StatusOK, shelterRemoveRolePageData{
		basePageData: basePageData{
			LoginSession: loginSessionData,
		},
		Shelter: shelter,
		User:    targetUser,
		Role:    targetRole,
	})
}

func (s *ShelterRemoveRoleHandler) renderPage(w http.ResponseWriter, status int, data shelterRemoveRolePageData) {
	err := RenderPage(w, shelterRemoveRolePage, status, data)
	if err != nil {
		s.Log.Error("Unable to render page.", "error", err.Error())
		renderErrorPage(w, errorPageData{
			basePageData: data.basePageData,
			Status:       http.StatusInternalServerError,
			Message:      clientMessageUnexpectedError,
		})
		return
	}
}

type ShelterEditRoleHandler struct {
	Log          *slog.Logger
	SessionStore *CookieSessionStore
	ShelterStore interface {
		shelterGetterWithRole
		shelterRoleGetter
		shelterRoleEditor
	}
	UserStore       userGetter
	ShelterRolesURL string
}

type shelterRoleEditor interface {
	EditShelterRole(ctx context.Context, shelterID string, userID string, role ShelterRole) error
}

type shelterEditRolePageData struct {
	basePageData
	ShelterName    string
	UserID         string
	UserEmail      string
	RoleField      ShelterRole
	RoleFieldError string
}

var shelterEditRolePage = template.Must(template.ParseFS(embedFS, "templates/pages/shelter/edit_role.html", "templates/pages/base.html"))

func (s *ShelterEditRoleHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var loginSessionData *loginSession
	s.SessionStore.Decode(r, sessionKeyLoginSession, &loginSessionData)

	shelterID := r.PathValue("shelter_id")

	cfg := shelterRoleGuardConfig{
		store:        s.ShelterStore,
		log:          s.Log,
		loginSession: loginSessionData,
		shelterID:    shelterID,
		allowedRoles: []ShelterRole{ShelterRoleSuperAdmin},
	}
	shelter, _, shouldReturn := shelterRoleGuard(r.Context(), w, cfg)
	if shouldReturn {
		return
	}

	targetID := r.URL.Query().Get("user-id")
	targetRole, err := s.ShelterStore.GetShelterRole(r.Context(), shelterID, targetID)
	if err != nil {
		if errors.Is(err, ErrNoShelterRole) {
			s.Log.Debug("This user does not have a role assigned to this shelter.", "shelter_id", shelterID, "user_id", targetID)

			flashData := newFlash(flashLevelError, "The user does not have a role assigned to this shelter.")
			s.SessionStore.Encode(w, sessionKeyFlash, flashData, flashMaxAge)

			redirectURL := strings.ReplaceAll(s.ShelterRolesURL, "{shelter_id}", shelter.ID)
			http.Redirect(w, r, redirectURL, http.StatusSeeOther)
			return
		}

		s.Log.Error("Unable to get target user shelter role.", "shelter_id", shelterID, "user_id", targetID)

		flashData := newFlash(flashLevelError, clientMessageUnexpectedError)
		s.SessionStore.Encode(w, sessionKeyFlash, flashData, flashMaxAge)

		redirectURL := strings.ReplaceAll(s.ShelterRolesURL, "{shelter_id}", shelter.ID)
		http.Redirect(w, r, redirectURL, http.StatusSeeOther)
		return
	}

	if targetRole == ShelterRoleSuperAdmin {
		flashData := newFlash(flashLevelError, "Super admin are not allowed to be edited.")
		s.SessionStore.Encode(w, sessionKeyFlash, flashData, flashMaxAge)

		redirectURL := strings.ReplaceAll(s.ShelterRolesURL, "{shelter_id}", shelter.ID)
		http.Redirect(w, r, redirectURL, http.StatusSeeOther)
		return
	}

	target, err := s.UserStore.GetUser(r.Context(), targetID)
	if err != nil {
		s.Log.Error("Unable to get target user.", "user_id", targetID)

		flashData := newFlash(flashLevelError, clientMessageUnexpectedError)
		s.SessionStore.Encode(w, sessionKeyFlash, flashData, flashMaxAge)

		redirectURL := strings.ReplaceAll(s.ShelterRolesURL, "{shelter_id}", shelter.ID)
		http.Redirect(w, r, redirectURL, http.StatusSeeOther)
		return
	}

	if r.Method == http.MethodPost {
		roleField := ShelterRole(r.FormValue("role"))
		var roleFieldError string
		if roleField == "" {
			roleFieldError = "Please fill out this field."
		} else if !slices.Contains([]ShelterRole{ShelterRoleAdmin, ShelterRoleEditor}, roleField) {
			roleFieldError = "Value is invalid role."
		}

		if roleFieldError != "" {
			s.Log.Debug("Role field validation failed.", "error", roleFieldError, "role_field", roleField)
			s.renderPage(w, http.StatusUnprocessableEntity, shelterEditRolePageData{
				basePageData: basePageData{
					LoginSession: loginSessionData,
				},
				ShelterName:    shelter.Name,
				UserID:         targetID,
				UserEmail:      target.Email,
				RoleField:      roleField,
				RoleFieldError: roleFieldError,
			})
			return
		}

		err := s.ShelterStore.EditShelterRole(r.Context(), shelterID, targetID, roleField)
		if err != nil {
			s.Log.Error("Unexpected error while editing shelter role.", "error", err.Error(), "shelter_id", shelterID, "user_id", targetID, "role", roleField)

			flashData := newFlash(flashLevelError, clientMessageUnexpectedError)
			s.SessionStore.Encode(w, sessionKeyFlash, flashData, flashMaxAge)

			redirectURL := strings.ReplaceAll(s.ShelterRolesURL, "{shelter_id}", shelterID)
			http.Redirect(w, r, redirectURL, http.StatusSeeOther)
			return
		}

		s.Log.Info("Shelter role was successfully edited.", "shelter_id", shelterID, "user_id", targetID, "new_role", roleField)

		message := fmt.Sprintf("%v was role assigned the role of %v", target.Email, roleField.String())
		flashData := newFlash(flashLevelSuccess, message)
		s.SessionStore.Encode(w, sessionKeyFlash, flashData, flashMaxAge)

		redirectURL := strings.ReplaceAll(s.ShelterRolesURL, "{shelter_id}", shelterID)
		http.Redirect(w, r, redirectURL, http.StatusSeeOther)
		return
	}

	s.renderPage(w, http.StatusOK, shelterEditRolePageData{
		basePageData: basePageData{
			LoginSession: loginSessionData,
		},
		ShelterName: shelter.Name,
		UserID:      targetID,
		UserEmail:   target.Email,
		RoleField:   targetRole,
	})
}

func (s *ShelterEditRoleHandler) renderPage(w http.ResponseWriter, status int, data shelterEditRolePageData) {
	err := RenderPage(w, shelterEditRolePage, http.StatusOK, data)
	if err != nil {
		s.Log.Error("Unable to render page.", "error", err.Error())
		renderErrorPage(w, errorPageData{
			basePageData: data.basePageData,
			Status:       http.StatusInternalServerError,
			Message:      clientMessageUnexpectedError,
		})
		return
	}
}

type shelterRoleGuardConfig struct {
	store        shelterGetterWithRole
	shelterID    string
	log          *slog.Logger
	loginSession *loginSession
	allowedRoles []ShelterRole
}

func shelterRoleGuard(ctx context.Context, w http.ResponseWriter, cfg shelterRoleGuardConfig) (shelter *Shelter, role ShelterRole, shouldReturn bool) {
	if cfg.loginSession == nil {
		cfg.log.Debug("Unauthorized. User is not logged in.")
		renderErrorPage(w, errorPageData{
			Status:  http.StatusUnauthorized,
			Message: "Unauthorized. Please login first.",
		})
		return nil, ShelterNoRole, true
	}

	var err error
	shelter, role, err = cfg.store.GetShelterWithRole(ctx, cfg.shelterID, cfg.loginSession.UserID)
	if err != nil {
		if errors.Is(err, ErrNoShelter) {
			cfg.log.Debug("Shelter not found.", "shelter_id", cfg.shelterID)
			renderErrorPage(w, errorPageData{
				basePageData: basePageData{
					LoginSession: cfg.loginSession,
				},
				Status:  http.StatusNotFound,
				Message: "Shelter doesn't exists.",
			})
			return nil, ShelterNoRole, true
		}

		cfg.log.Error("Unable to get shelter role.", "shelter_id", cfg.shelterID, "user_id", cfg.loginSession.UserID)
		renderErrorPage(w, errorPageData{
			basePageData: basePageData{
				LoginSession: cfg.loginSession,
			},
			Status:  http.StatusInternalServerError,
			Message: clientMessageUnexpectedError,
		})
		return nil, ShelterNoRole, true
	}

	if !slices.Contains(cfg.allowedRoles, role) {
		cfg.log.Debug("User is not authorized to perform action for this shelter.", "shelter_id", cfg.shelterID, "user_id", cfg.loginSession.UserID, "role", role)
		renderErrorPage(w, errorPageData{
			basePageData: basePageData{
				LoginSession: cfg.loginSession,
			},
			Status:  http.StatusUnauthorized,
			Message: "Unauthorized.",
		})
		return nil, ShelterNoRole, true
	}

	return shelter, role, false
}

type PostPetHandler struct {
	Log               *slog.Logger
	SessionStore      *CookieSessionStore
	ShelterRoleGetter shelterRoleGetter
	ImageStore        multipartImageStore
	PetRegistry       petRegistry
}

type multipartImageStore interface {
	StoreMultipart([]*multipart.FileHeader) ([]Image, error)
}

type NewPet struct {
	Name              string
	Gender            Gender
	Type              PetType
	BirthDate         time.Time
	IsBirthDateApprox bool
	Images            []Image
	Description       string
}

type petRegistry interface {
	RegisterPet(ctx context.Context, shelterID string, data NewPet) (*Pet, error)
}

type postPetPageData struct {
	basePageData
	Flash       *flash
	FieldValues postPetValues
	FieldErrors postPetErrors
}

type postPetValues struct {
	Name              string
	Gender            string
	Type              string
	BirthDate         string
	IsBirthDateApprox bool
	Images            []*multipart.FileHeader
	Description       string
}

type postPetErrors struct {
	Name        string
	Gender      string
	Type        string
	BirthDate   string
	Images      string
	Description string
}

var postPetPage = template.Must(template.ParseFS(embedFS, "templates/pages/shelter/post_pet.html", "templates/pages/base.html"))

func (p *PostPetHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var loginSessionData *loginSession
	p.SessionStore.Decode(r, sessionKeyLoginSession, &loginSessionData)

	if loginSessionData == nil {
		p.Log.Debug("Unauthenticated. User is not logged in.")
		renderErrorPage(w, errorPageData{
			Status:  http.StatusUnauthorized,
			Message: "Unauthorized. Please login first.",
		})
		return
	}

	shelterID := r.PathValue("shelter_id")
	role, err := p.ShelterRoleGetter.GetShelterRole(r.Context(), shelterID, loginSessionData.UserID)
	if err != nil && !errors.Is(err, ErrNoShelterRole) {
		p.Log.Error(
			"Unexpected error while getting shelter role.",
			"shelter_id", shelterID,
			"user_id", loginSessionData.UserID,
		)
		renderErrorPage(w, errorPageData{
			basePageData: basePageData{
				LoginSession: loginSessionData,
			},
			Status:  http.StatusInternalServerError,
			Message: clientMessageUnexpectedError,
		})
		return
	}

	allowedRoles := []ShelterRole{ShelterRoleSuperAdmin, ShelterRoleAdmin, ShelterRoleEditor}
	if errors.Is(err, ErrNoShelterRole) || !slices.Contains(allowedRoles, role) {
		p.Log.Debug(
			"Unauthorized. The current user doesn't have a role for the shelter.",
			"shelter_id", shelterID,
			"user_id", loginSessionData.UserID,
			"role", role,
		)
		renderErrorPage(w, errorPageData{
			basePageData: basePageData{
				LoginSession: loginSessionData,
			},
			Status:  http.StatusUnauthorized,
			Message: "Unauthorized.",
		})
		return
	}

	if r.Method == http.MethodPost {
		err := r.ParseMultipartForm(10_000_000)
		if err != nil {
			p.renderPage(w, http.StatusInternalServerError, postPetPageData{
				basePageData: basePageData{
					LoginSession: loginSessionData,
				},
				Flash: newFlash(flashLevelError, clientMessageUnexpectedError),
			})
			return
		}

		fieldValues := postPetValues{
			Name:              strings.TrimSpace(r.FormValue("name")),
			Gender:            r.FormValue("gender"),
			Type:              r.FormValue("type"),
			BirthDate:         r.FormValue("birth-date"),
			IsBirthDateApprox: r.FormValue("is-birth-date-approx") == "on",
			Images:            r.MultipartForm.File["images"],
			Description:       strings.TrimSpace(r.FormValue("description")),
		}
		fieldErrors, valid := p.validate(fieldValues)
		if !valid {
			p.Log.Debug("Field validation failed.", "field_errors", fieldErrors)
			p.renderPage(w, http.StatusUnprocessableEntity, postPetPageData{
				basePageData: basePageData{
					LoginSession: loginSessionData,
				},
				FieldValues: fieldValues,
				FieldErrors: fieldErrors,
			})
			return
		}

		images, err := p.ImageStore.StoreMultipart(fieldValues.Images)
		if err != nil {
			p.Log.Error("Unable to store images.", "error", err.Error())
			p.renderPage(w, http.StatusInternalServerError, postPetPageData{
				basePageData: basePageData{
					LoginSession: loginSessionData,
				},
				Flash:       newFlash(flashLevelError, clientMessageUnexpectedError),
				FieldValues: fieldValues,
			})
			return
		}

		birthDate, _ := http.ParseTime(fieldValues.BirthDate)

		pet, err := p.PetRegistry.RegisterPet(r.Context(), shelterID, NewPet{
			Name:        fieldValues.Name,
			Gender:      Gender(fieldValues.Gender),
			Type:        PetType(fieldValues.Type),
			BirthDate:   birthDate,
			Images:      images,
			Description: fieldValues.Description,
		})
		if err != nil {
			p.Log.Error("Unable to register pet.", "shelter_id", shelterID, "user_id", loginSessionData.UserID, "field_values", fieldValues, "error", err.Error())
			p.renderPage(w, http.StatusInternalServerError, postPetPageData{
				basePageData: basePageData{
					LoginSession: loginSessionData,
				},
				Flash: newFlash(flashLevelError, clientMessageUnexpectedError),
			})
			return
		}

		p.Log.Info("New pet was registered.", "shelter_id", shelterID, "user_id", loginSessionData.UserID, "pet_id", pet.ID)

		p.renderPage(w, http.StatusOK, postPetPageData{
			basePageData: basePageData{
				LoginSession: loginSessionData,
			},
			Flash: newFlash(flashLevelSuccess, "New pet was posted."),
		})
		return
	}

	p.renderPage(w, http.StatusOK, postPetPageData{
		basePageData: basePageData{
			LoginSession: loginSessionData,
		},
	})
}

func (p *PostPetHandler) validate(fieldValue postPetValues) (fieldErrors postPetErrors, valid bool) {
	if l := len(fieldValue.Name); l == 0 {
		fieldErrors.Name = "Please fill out this field."
	} else if l < 2 {
		fieldErrors.Name = "Name is too short."
	} else if l > 20 {
		fieldErrors.Name = "Name is too long. It must not exceed 20 character long."
	}

	if fieldValue.Gender == "" {
		fieldErrors.Gender = "Please fill out this field."
	} else if fieldValue.Gender != string(GenderMale) && fieldValue.Gender != string(GenderFemale) {
		fieldErrors.Gender = "Gender is invalid."
	}

	if fieldValue.Type == "" {
		fieldErrors.Type = "Please fill out this field."
	} else if fieldValue.Type != string(PetTypeCat) && fieldValue.Type != string(PetTypeDog) {
		fieldErrors.Type = "Type is invalid."
	}

	if l := len(fieldValue.Images); l != 4 {
		fieldErrors.Images = "Please upload at least 4 images"
	}

	if fieldValue.BirthDate == "" {
		fieldErrors.BirthDate = "Please fill out this field."
	} else if parsedBirthDate, err := http.ParseTime(fieldValue.BirthDate); err != nil || parsedBirthDate.After(time.Now()) {
		fieldErrors.BirthDate = "Date is invalid"
	}

	if l := len(fieldValue.Description); l == 0 {
		fieldErrors.Description = "Please fill out this field."
	} else if l < 250 {
		fieldErrors.Description = "Description is too short. It must be at least 250 characters long."
	} else if l > 2500 {
		fieldErrors.Description = "Description is too long. It must not exceed 2,500 characteres long."
	}

	valid = fieldErrors.Name == "" &&
		fieldErrors.Gender == "" &&
		fieldErrors.Type == "" &&
		fieldErrors.Images == "" &&
		fieldErrors.Description == ""

	return fieldErrors, valid
}

func (p *PostPetHandler) renderPage(w http.ResponseWriter, status int, data postPetPageData) {
	err := RenderPage(w, postPetPage, status, data)
	if err != nil {
		p.Log.Error("Unable to render page.", "error", err.Error())
		renderErrorPage(w, errorPageData{
			basePageData: basePageData{
				LoginSession: data.LoginSession,
			},
			Status:  http.StatusInternalServerError,
			Message: clientMessageUnexpectedError,
		})
		return
	}
}
