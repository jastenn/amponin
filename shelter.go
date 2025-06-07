package main

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"mime/multipart"
	"net/http"
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

		flashData := newFlash(flashLevelSuccess, "Successfully registered a new shelter.")
		rh.SessionStore.Encode(w, sessionKeyFlash, flashData, flashMaxAge)

		redirectURL := strings.ReplaceAll(rh.SuccessRedirectURL, "{shelter_id}", shelter.ID)
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
	shelterID := r.PathValue("shelter_id")
	var loginSessionData *loginSession
	g.SessionStore.Decode(r, sessionKeyLoginSession, &loginSessionData)
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

	var flashData *flash
	g.SessionStore.Decode(r, sessionKeyFlash, &flashData)
	err = RenderPage(w, getShelterByIDPage, http.StatusOK, shelterByIDPageData{
		basePageData: basePageData{
			LoginSession: loginSessionData,
		},
		Role:    role,
		Flash:   flashData,
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

	if loginSessionData == nil {
		s.Log.Debug("Unauthorized. User is not logged in.")
		renderErrorPage(w, errorPageData{
			Status:  http.StatusUnauthorized,
			Message: "Unauthorized. Please login first.",
		})
		return
	}

	shelterID := r.PathValue("shelter_id")
	shelter, role, err := s.ShelterGetter.GetShelterWithRole(r.Context(), shelterID, loginSessionData.UserID)
	if err != nil {
		if errors.Is(err, ErrNoShelter) {
			s.Log.Debug("Shelter doesn't exists.", "shelter_id", shelterID)
			s.NotFoundHandler.ServeHTTP(w, r)
			return
		}

		s.Log.Error("Unable to get shelter by id.", "error", err.Error())
		renderErrorPage(w, errorPageData{
			basePageData: basePageData{
				LoginSession: loginSessionData,
			},
			Status:  http.StatusInternalServerError,
			Message: clientMessageUnexpectedError,
		})
		return
	}

	if role == ShelterNoRole {
		s.Log.Debug("Unauthorized. User doesn't manage this shelter.", "shelter_id", shelterID, "user_id", loginSessionData.UserID)
		renderErrorPage(w, errorPageData{
			basePageData: basePageData{
				LoginSession: loginSessionData,
			},
			Status:  http.StatusUnauthorized,
			Message: "Unauthorized.",
		})
		return
	}

	err = RenderPage(w, shelterSettingsPage, http.StatusOK, shelterSettingsPageData{
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

	if loginSessionData == nil {
		e.Log.Debug("Unauthorized. User is not logged in.")
		renderErrorPage(w, errorPageData{
			Status:  http.StatusUnauthorized,
			Message: "Unauthorized. Please login first",
		})
		return
	}

	shelterID := r.PathValue("shelter_id")

	shelter, role, err := e.ShelterStore.GetShelterWithRole(r.Context(), shelterID, loginSessionData.UserID)
	if err != nil {
		if errors.Is(err, ErrNoShelter) {
			e.Log.Debug("Shelter not found.", "shelter_id", shelterID)
			e.NotFoundHandler.ServeHTTP(w, r)
			return
		}

		e.Log.Error("Unable to get shelter role.", "shelter_id", shelterID, "user_id", loginSessionData.UserID)
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
		e.Log.Debug("User is not authorized to perform action for this shelter.", "shelter_id", shelterID, "user_id", loginSessionData.UserID, "role", role)
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

		flashData := newFlash(flashLevelSuccess, "Shelter info was updated successfully.")
		e.SessionStore.Encode(w, sessionKeyFlash, flashData, flashMaxAge)

		redirectURL := strings.ReplaceAll(e.SuccessRedirectURL, "{shelter_id}", shelterID)
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
