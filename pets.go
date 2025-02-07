package main

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"mime/multipart"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/alexedwards/scs/v2"
)

var (
	ErrNoPet = errors.New("pet not found")
)

type Pet struct {
	ID                string
	ShelterID         string
	Name              string
	Type              PetType
	Gender            Gender
	BirthDate         time.Time
	IsBirthDateApprox bool
	Description       string
	ImageURLs         []string
	RegisteredAt      time.Time
	UpdatedAt         time.Time
}

type PetType string

const (
	PetTypeDog PetType = "dog"
	PetTypeCat PetType = "cat"
)

type Gender string

const (
	GenderMale   Gender = "male"
	GenderFemale Gender = "female"
)

type PostPetTemplateData struct {
	LoginSession *SessionUser
	Flash        *Flash
	ShelterID    string
	Values       PetPostValues
	Errors       PetPostErrors
}

type PetPostValues struct {
	Name              string
	Type              string
	Gender            string
	BirthDate         string
	IsBirthDateApprox string
	Description       string
	Images            []*multipart.FileHeader
}

func (p PetPostValues) Parse() (parsed ParsedPetPostValues, fieldErrors PetPostErrors, ok bool) {
	var err error
	ok = true

	if l := len(p.Name); l == 0 {
		fieldErrors.Name = "Please fill out this field."
		ok = false
	} else if l == 1 {
		fieldErrors.Name = "Value is too short."
		ok = false
	} else if l > 16 {
		fieldErrors.Name = "Value is too long, it must not exceed 16 characters long."
	}

	gender := Gender(p.Gender)
	if p.Gender == "" {
		fieldErrors.Gender = "Please fill out this field."
		ok = false
	} else if gender != GenderMale && gender != GenderFemale {
		fieldErrors.Gender = "Value is invalid gender."
		ok = false
	}

	petType := PetType(p.Type)
	if p.Type == "" {
		fieldErrors.Type = "Please fill out this field."
		ok = false
	} else if petType != PetTypeCat && petType != PetTypeDog {
		fieldErrors.Type = "Value is invalid pet type."
		ok = false
	}

	var birthDate time.Time
	if p.BirthDate == "" {
		fieldErrors.BirthDate = "Please fill out this field."
		ok = false
	} else if birthDate, err = time.Parse(time.DateOnly, p.BirthDate); err != nil {
		fmt.Println(p.BirthDate)
		fieldErrors.BirthDate = "Value is invalid date."
		ok = false
	}

	var isBirthDateApprox bool
	if p.IsBirthDateApprox == "true" {
		isBirthDateApprox = true
	}

	if l := len(p.Images); l == 0 {
		fieldErrors.Images = "Please fill out this field."
		ok = false
	} else if l > 4 {
		fieldErrors.Images = "Only 4 images is allowed."
		ok = false
	}

	if l := len(p.Description); l == 0 {
		fieldErrors.Description = "Please fill out this field."
		ok = false
	} else if l < 250 {
		fieldErrors.Description = "Value is too short, it must be at least 250 characters long."
		ok = false
	} else if l > 2500 {
		fieldErrors.Description = "Value is too long, it must not exceed 2500 characters long."
		ok = false
	}

	if !ok {
		return ParsedPetPostValues{}, fieldErrors, ok
	}

	return ParsedPetPostValues{
		Name:              p.Name,
		Type:              petType,
		Gender:            gender,
		BirthDate:         birthDate,
		IsBirthDateApprox: isBirthDateApprox,
		Description:       p.Description,
		Images:            p.Images,
	}, PetPostErrors{}, true
}

type ParsedPetPostValues struct {
	Name              string
	Type              PetType
	Gender            Gender
	BirthDate         time.Time
	IsBirthDateApprox bool
	Description       string
	Images            []*multipart.FileHeader
}

type PetPostErrors struct {
	Name        string
	Type        string
	BirthDate   string
	Gender      string
	Description string
	Images      string
}

type PostPetHandler struct {
	Log               *slog.Logger
	TemplateFS        fs.FS
	SessionManager    *scs.SessionManager
	ShelterRoleGetter ShelterRoleGetter
	LoginRedirectURL  string

	postPetTemplateCache *template.Template
}

func (p *PostPetHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	shelterID := r.PathValue("id")
	if shelterID == "" {
		panic("shelter id is missing")
	}

	sessionUser, _ := GetSessionUser(p.SessionManager, r.Context())
	if sessionUser == nil {
		p.Log.Debug("Unauthorized, user is not logged in.")
		PutSessionFlash(
			p.SessionManager, r.Context(),
			"Please login first.", FlashLevelError,
		)
		redirectURL := strings.ReplaceAll(p.LoginRedirectURL, "{shelter_id}", shelterID)
		http.Redirect(w, r, redirectURL, http.StatusSeeOther)
		return
	}

	_, err := p.ShelterRoleGetter.GetShelterRoleByID(r.Context(), shelterID, sessionUser.UserID)
	if err != nil {
		if errors.Is(err, ErrNoShelterRole) {
			p.Log.Debug("User doesn't have role on shelter provided.")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		p.Log.Error("Unable to get users role on shelter.", "reason", err.Error())
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if p.postPetTemplateCache == nil {
		var err error
		p.postPetTemplateCache, err = template.ParseFS(p.TemplateFS, "base.html", "post_pet.html")
		if err != nil {
			panic("unable to parse template: " + err.Error())
		}
	}
	err = ExecuteTemplate(p.postPetTemplateCache, w, "base.html", PostPetTemplateData{
		LoginSession: sessionUser,
		ShelterID:    shelterID,
	})
	if err != nil {
		panic("unable to execute template: " + err.Error())
	}
}

type FileStore interface {
	Save(dir string, file io.Reader) (url string, err error)
}

type NewPet struct {
	ShelterID         string
	Name              string
	Type              PetType
	Gender            Gender
	BirthDate         time.Time
	IsBirthDateApprox bool
	Description       string
	ImageURLs         []string
}

type PetRegistry interface {
	RegisterPet(ctx context.Context, data NewPet) (*Pet, error)
}

type DoPetPostHandler struct {
	TemplateFS         fs.FS
	FileStore          FileStore
	SessionManager     *scs.SessionManager
	Log                *slog.Logger
	PetRegistry        PetRegistry
	ShelterRoleGetter  ShelterRoleGetter
	LoginRedirectURL   string
	SuccessRedirectURL string

	postPetTemplateCache *template.Template
}

func (d *DoPetPostHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	shelterID := r.PathValue("shelter_id")

	loginSession, _ := GetSessionUser(d.SessionManager, r.Context())
	if loginSession == nil {
		d.Log.Debug("Unauthorized, user is not logged in.")
		PutSessionFlash(
			d.SessionManager, r.Context(),
			"Please login first.", FlashLevelError,
		)
		redirectURL := strings.ReplaceAll(d.LoginRedirectURL, "{shelter_id}", shelterID)
		http.Redirect(w, r, redirectURL, http.StatusSeeOther)
		return
	}

	_, err := d.ShelterRoleGetter.GetShelterRoleByID(r.Context(), shelterID, loginSession.UserID)
	if err != nil {
		if errors.Is(err, ErrNoShelterRole) {
			d.Log.Debug("User doesn't have role on shelter provided.")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		d.Log.Error("Unable to get users role on shelter.", "reason", err.Error())
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	err = r.ParseMultipartForm(10_485_760)
	if err != nil {
		d.Log.Debug("The form is not multipart")
		d.RenderTemplate(w, PostPetTemplateData{
			ShelterID: shelterID,
			Flash: &Flash{
				Level:   FlashLevelError,
				Message: "Form must be a multipart.",
			},
		})
		return
	}

	fieldValues := PetPostValues{
		Name:              r.PostFormValue("name"),
		BirthDate:         r.PostFormValue("birth-date"),
		Type:              r.PostFormValue("type"),
		IsBirthDateApprox: r.PostFormValue("is-birth-date-approx"),
		Gender:            r.PostFormValue("gender"),
		Description:       r.PostFormValue("description"),
		Images:            r.MultipartForm.File["images"],
	}
	parsed, fieldErrors, ok := fieldValues.Parse()
	if !ok {
		d.Log.Debug("Field validation failed.", "field_values", fieldValues, "field_errors", fieldErrors)
		d.RenderTemplate(w, PostPetTemplateData{
			ShelterID:    shelterID,
			LoginSession: loginSession,
			Errors:       fieldErrors,
			Values:       fieldValues,
		})
		return
	}

	var images []string
	for _, hfile := range parsed.Images {
		file, err := hfile.Open()
		if err != nil {
			d.Log.Debug("Unable to process one of the image", "reason", err.Error())
			d.RenderTemplate(w, PostPetTemplateData{
				ShelterID:    shelterID,
				LoginSession: loginSession,
				Errors:       fieldErrors,
				Values:       fieldValues,
			})
			return
		}
		defer file.Close()

		filepath := filepath.Join("shelters", shelterID, hfile.Filename)
		url, err := d.FileStore.Save(filepath, file)
		if err != nil {
			d.Log.Debug("Unable to save one of the image", "reason", err.Error())
			d.RenderTemplate(w, PostPetTemplateData{
				ShelterID:    shelterID,
				LoginSession: loginSession,
				Errors:       fieldErrors,
				Values:       fieldValues,
			})
			return
		}
		images = append(images, url)
	}

	pet, err := d.PetRegistry.RegisterPet(r.Context(), NewPet{
		ShelterID:         shelterID,
		Name:              parsed.Name,
		Type:              parsed.Type,
		Gender:            parsed.Gender,
		BirthDate:         parsed.BirthDate,
		IsBirthDateApprox: parsed.IsBirthDateApprox,
		Description:       parsed.Description,
		ImageURLs:         images,
	})
	if err != nil {
		d.Log.Error("Unable to register pet", "reason", err.Error(), "shelter_id", shelterID, "user_id", loginSession.UserID)
		d.RenderTemplate(w, PostPetTemplateData{
			ShelterID:    shelterID,
			LoginSession: loginSession,
			Flash: &Flash{
				Level:   FlashLevelError,
				Message: "Unexpected error occurred. Please try again later.",
			},
			Values: fieldValues,
		})
		return
	}

	d.Log.Debug("New pet was registered.", "shelter_id", shelterID, "pet_id", pet.ID)
	PutSessionFlash(
		d.SessionManager, r.Context(),
		"New pet was registered.", FlashLevelSuccess,
	)
	redirectURL := strings.ReplaceAll(d.SuccessRedirectURL, "{pet_id}", pet.ID)
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

func (d *DoPetPostHandler) RenderTemplate(w http.ResponseWriter, data PostPetTemplateData) {
	if d.postPetTemplateCache == nil {
		var err error
		d.postPetTemplateCache, err = template.ParseFS(d.TemplateFS, "base.html", "post_pet.html")
		if err != nil {
			panic("unable to parse template: " + err.Error())
		}
	}
	err := ExecuteTemplate(d.postPetTemplateCache, w, "base.html", data)
	if err != nil {
		panic("unable to execute template: " + err.Error())
	}
}

type PetSearchQuery struct {
	Location string
	Type     string
}

type PetsTemplateData struct {
	LoginSession *SessionUser
	Flash        *Flash
	FormError    string
	Query        PetSearchQuery
	Results      []FindPetByLocationResult
}

type FindPetByLocationResult struct {
	Pet      *Pet
	Distance int
	Address  string
}

type FindPetByLocationFilter struct {
	Type        *PetType
	MaxDistance *int
}

type PetsHandler struct {
	Log                 *slog.Logger
	TemplateFS          fs.FS
	SessionManager      *scs.SessionManager
	PetFinderByLocation interface {
		FindPetByLocation(context.Context, *Coordinates, FindPetByLocationFilter) ([]FindPetByLocationResult, error)
	}

	petsTemplateCache *template.Template
}

func (i *PetsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	flash, _ := PopSessionFlash(i.SessionManager, r.Context())
	loginSession, _ := GetSessionUser(i.SessionManager, r.Context())

	query := PetSearchQuery{
		Location: r.FormValue("location"),
		Type:     r.FormValue("type"),
	}

	var results []FindPetByLocationResult
	if query.Location != "" {
		parsedLocation, err := ParseCoordinates(query.Location)
		if err != nil {
			i.Log.Debug("Coordinates is invaild.", "coordinates", query.Location)
			i.RenderTemplate(w, PetsTemplateData{
				Flash:        flash,
				LoginSession: loginSession,
				FormError:    "Location is invalid.",
				Query:        query,
			})
			return
		}

		var petType *PetType
		if query.Type != "any" && query.Type != "" {
			if query.Type != string(PetTypeCat) && query.Type != string(PetTypeDog) {
				i.Log.Debug("Type is invaild.", "coordinates", query.Location)
				i.RenderTemplate(w, PetsTemplateData{
					Flash:        flash,
					LoginSession: loginSession,
					FormError:    "Type is invalid.",
					Query:        query,
				})
				return
			}
			tmp := PetType(query.Type)
			petType = &tmp
		}

		results, err = i.PetFinderByLocation.FindPetByLocation(r.Context(), parsedLocation, FindPetByLocationFilter{
			Type: petType,
		})
		if err != nil {
			i.Log.Error("Unable to find pet by location.", "reason", err.Error())
			i.RenderTemplate(w, PetsTemplateData{
				LoginSession: loginSession,
				Flash: &Flash{
					Level:   FlashLevelError,
					Message: "Something went wrong. Please try again later.",
				},
				Query: query,
			})
			return
		}
	}

	i.Log.Debug("Pet search by location successful.", "total_result", len(results))
	i.RenderTemplate(w, PetsTemplateData{
		LoginSession: loginSession,
		Flash:        flash,
		Query:        query,
		Results:      results,
	})
}

func (i *PetsHandler) RenderTemplate(w http.ResponseWriter, data PetsTemplateData) {
	if i.petsTemplateCache == nil {
		var err error
		i.petsTemplateCache, err = template.New("pets.html").
			Funcs(template.FuncMap{
				"fmt_distance": fmtDistance,
			}).
			ParseFS(i.TemplateFS, "base.html", "pets.html")
		if err != nil {
			panic("unable to parse index template: " + err.Error())
		}
	}
	err := ExecuteTemplate(i.petsTemplateCache, w, "base.html", data)
	if err != nil {
		panic("unable to execute index template: " + err.Error())
	}
}

type PetByIDTemplateData struct {
	LoginSession *SessionUser
	Flash        *Flash
	Pet          *Pet
	Shelter      *Shelter
}

type PetByIDHandler struct {
	Log             *slog.Logger
	TemplateFS      fs.FS
	SessionManager  *scs.SessionManager
	NotFoundHandler http.Handler
	PetGetter       interface {
		GetPetByID(ctx context.Context, petID string) (*Pet, error)
	}
	ShelterGetter interface {
		GetShelterByID(ctx context.Context, shelterID string) (*Shelter, error)
	}

	petByIDTemplateCache *template.Template
}

func (p *PetByIDHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	loginSession, _ := p.SessionManager.Get(r.Context(), SessionKeyLoginSession).(*SessionUser)
	flash, _ := p.SessionManager.Pop(r.Context(), SessionKeyFlash).(*Flash)

	petID := r.PathValue("pet_id")

	pet, err := p.PetGetter.GetPetByID(r.Context(), petID)
	if err != nil {
		if errors.Is(err, ErrNoPet) {
			p.Log.Debug("No pet with matching id was found.", "pet_id", petID)
			p.NotFoundHandler.ServeHTTP(w, r)
			return
		}

		panic("unexpected error occurred: " + err.Error())
	}

	shelter, err := p.ShelterGetter.GetShelterByID(r.Context(), pet.ShelterID)
	if err != nil {
		panic("unexpected error occurred: " + err.Error())
	}

	if p.petByIDTemplateCache == nil {
		p.petByIDTemplateCache, err = template.New("pet_by_id").Funcs(template.FuncMap{
			"calc_age": calculateAge,
		}).ParseFS(p.TemplateFS, "base.html", "pet_by_id.html")
		if err != nil {
			panic("unable to parse pet_by_id.html: " + err.Error())
		}
	}

	err = ExecuteTemplate(p.petByIDTemplateCache, w, "base.html", PetByIDTemplateData{
		LoginSession: loginSession,
		Flash:        flash,
		Shelter:      shelter,
		Pet:          pet,
	})
	if err != nil {
		panic("unable to execute pet_by_id.html: " + err.Error())
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
