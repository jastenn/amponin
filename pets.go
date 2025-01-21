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
)

type Pet struct {
	ID                string
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
	LoginSession *LoginSession
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
	SessionStore      *CookieStore
	ShelterRoleGetter ShelterRoleGetter
	LoginRedirectURL  string

	postPetTemplateCache *template.Template
}

func (p *PostPetHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	shelterID := r.PathValue("id")
	if shelterID == "" {
		panic("shelter id is missing")
	}

	loginSession, _ := GetLoginSession(p.SessionStore, w, r)
	if loginSession == nil {
		p.Log.Debug("Unauthorized, user is not logged in.")
		p.SessionStore.SetFlash(w, "Please login first.", FlashLevelError)
		redirectURL := strings.ReplaceAll(p.LoginRedirectURL, "{shelter_id}", shelterID)
		http.Redirect(w, r, redirectURL, http.StatusSeeOther)
		return
	}

	_, err := p.ShelterRoleGetter.GetShelterRoleByID(r.Context(), shelterID, loginSession.UserID)
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
		p.postPetTemplateCache, err = template.ParseFS(p.TemplateFS, "base.html", "post-pet.html")
		if err != nil {
			panic("unable to parse template: " + err.Error())
		}
	}
	err = ExecuteTemplate(p.postPetTemplateCache, w, "base.html", PostPetTemplateData{
		LoginSession: loginSession,
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
	TemplateFS        fs.FS
	FileStore         FileStore
	SessionStore      *CookieStore
	Log               *slog.Logger
	PetRegistry       PetRegistry
	ShelterRoleGetter ShelterRoleGetter
	LoginRedirectURL  string

	postPetTemplateCache *template.Template
}

func (d *DoPetPostHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	shelterID := r.PathValue("id")

	loginSession, _ := GetLoginSession(d.SessionStore, w, r)
	if loginSession == nil {
		d.Log.Debug("Unauthorized, user is not logged in.")
		d.SessionStore.SetFlash(w, "Please login first.", FlashLevelError)
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

		filename := strconv.FormatInt(time.Now().UnixMicro(), 10) + hfile.Filename
		filepath := filepath.Join("shelters", shelterID, filename)
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

	d.SessionStore.SetFlash(w, "New pet was registered.", FlashLevelSuccess)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (d *DoPetPostHandler) RenderTemplate(w http.ResponseWriter, data PostPetTemplateData) {
	if d.postPetTemplateCache == nil {
		var err error
		d.postPetTemplateCache, err = template.ParseFS(d.TemplateFS, "base.html", "post-pet.html")
		if err != nil {
			panic("unable to parse template: " + err.Error())
		}
	}
	err := ExecuteTemplate(d.postPetTemplateCache, w, "base.html", data)
	if err != nil {
		panic("unable to execute template: " + err.Error())
	}
}
