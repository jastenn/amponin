package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/alexedwards/scs/v2"
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

type PostPetHandler struct {
	Log                  *slog.Logger
	PageTemplateRenderer PageTemplateRenderer
	SessionManager       *scs.SessionManager
	ShelterRoleGetter    ShelterRoleGetter
}

func (p *PostPetHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sessionUser := GetSessionUser(r.Context())
	if sessionUser == nil {
		p.Log.Debug("Unauthorized request.")
		BasicHTTPError(w, http.StatusInternalServerError)
		return
	}

	shelterID := r.PathValue("shelter_id")

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

	err = p.PageTemplateRenderer.RenderPageTemplate(w, "post_pet.html", PostPetPage{
		BasePage: BasePage{
			SessionUser: sessionUser,
		},
		ShelterID: shelterID,
		Form: PetPostForm{
			FieldValidation: NewFieldValidation(),
		},
	})
	if err != nil {
		panic("unable to execute template: " + err.Error())
	}
}

type PostPetPage struct {
	BasePage
	Flash     *Flash
	ShelterID string
	Form      PetPostForm
}

type PetPostForm struct {
	Name              string
	Type              string
	Gender            string
	BirthDate         string
	IsBirthDateApprox string
	Description       string
	Images            []FormImageResult

	*FieldValidation
}

type DoPetPostHandler struct {
	PageTemplateRenderer PageTemplateRenderer
	FileStore            FileStore
	SessionManager       *scs.SessionManager
	Log                  *slog.Logger
	PetRegistry          interface {
		RegisterPet(ctx context.Context, data NewPet) (*Pet, error)
	}
	ShelterRoleGetter  ShelterRoleGetter
	LoginRedirectURL   string
	SuccessRedirectURL string
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

func (d *DoPetPostHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sessionUser := GetSessionUser(r.Context())
	if sessionUser == nil {
		d.Log.Debug("Unauthorized request")
		BasicHTTPError(w, http.StatusUnauthorized)
		return
	}

	shelterID := r.PathValue("shelter_id")

	_, err := d.ShelterRoleGetter.GetShelterRoleByID(r.Context(), shelterID, sessionUser.UserID)
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
		d.RenderPageTemplate(w, PostPetPage{
			ShelterID: shelterID,
			Flash:     NewFlash("Form must be a multipart.", FlashLevelError),
		})
		return
	}

	form := PetPostForm{
		Name:              r.PostFormValue("name"),
		BirthDate:         r.PostFormValue("birth-date"),
		Type:              r.PostFormValue("type"),
		IsBirthDateApprox: r.PostFormValue("is-birth-date-approx"),
		Gender:            r.PostFormValue("gender"),
		Description:       r.PostFormValue("description"),
		Images:            nil,
		FieldValidation:   NewFieldValidation(),
	}

	form.Images, err = FormImages(r, "images")
	form.Check(errors.Is(err, ErrUnexpectedFileType), "images", "File type not supported.")
	form.Check(err != nil, "images", "Unable to upload images.")

	form.Check(form.Name == "", "name", "Please fill out this field.")
	form.Check(len(form.Name) == 1, "name", "Value is too short.")
	form.Check(len(form.Name) == 16, "name", "Value is too long, it must not exceed 16 characters long.")
	form.Check(form.Gender == "", "gender", "Please fill out this field.")
	form.Check(
		form.Gender != string(GenderMale) && form.Gender != string(GenderFemale),
		"gender", "Value is invalid gender.",
	)
	form.Check(form.Type == "", "type", "Please fill out this field.")
	form.Check(
		form.Type != string(PetTypeCat) && form.Type != string(PetTypeDog),
		"type", "Value is invalid type.",
	)
	form.Check(form.BirthDate == "", "birth-date", "Please fill out this field.")
	form.Check(IsInvalidDate(form.BirthDate), "birth-date", "Value is invalid date.")
	form.Check(len(form.Images) == 0, "images", "Please fill out this field.")
	form.Check(len(form.Images) != 4, "images", "Please upload 4 images.")
	form.Check(form.Description == "", "description", "Please fill out this field.")
	form.Check(len(form.Description) < 250, "description", "Value is too short. It must be at least 250 characters long.")
	form.Check(len(form.Description) > 2500, "description", "Value is too long. It must not exceed 2500 characters long.")

	if !form.Valid() {
		d.Log.Debug("Field validation failed.", "field_errors", form.FieldErrors)
		d.RenderPageTemplate(w, PostPetPage{
			BasePage: BasePage{
				SessionUser: sessionUser,
			},
			ShelterID: shelterID,
			Form:      form,
		})
		return
	}

	var imageURLs []string
	for _, image := range form.Images {
		filepath := path.Join("shelters", shelterID, "pets", image.Filename)
		url, err := d.FileStore.Save(filepath, bytes.NewBuffer(image.Data))
		if err != nil {
			form.Add("images", "Unable to upload images.")
			d.RenderPageTemplate(w, PostPetPage{
				BasePage: BasePage{
					SessionUser: sessionUser,
				},
				ShelterID: shelterID,
				Form:      form,
			})
			return
		}

		imageURLs = append(imageURLs, url)
	}

	birthDate, err := time.Parse(time.DateOnly, form.BirthDate)
	if err != nil {
		panic(err)
	}

	pet, err := d.PetRegistry.RegisterPet(r.Context(), NewPet{
		ShelterID:         shelterID,
		Name:              form.Name,
		Type:              PetType(form.Type),
		Gender:            Gender(form.Gender),
		BirthDate:         birthDate,
		IsBirthDateApprox: form.IsBirthDateApprox == "true",
		Description:       form.Description,
		ImageURLs:         imageURLs,
	})
	if err != nil {
		d.Log.Error("Unable to register pet", "reason", err.Error(), "shelter_id", shelterID, "user_id", sessionUser.UserID)
		d.RenderPageTemplate(w, PostPetPage{
			ShelterID: shelterID,
			BasePage: BasePage{
				SessionUser: sessionUser,
			},
			Flash: &Flash{
				Level:   FlashLevelError,
				Message: "Unexpected error occurred. Please try again later.",
			},
			Form: form,
		})
		return
	}

	d.Log.Debug("New pet was registered.", "shelter_id", shelterID, "pet_id", pet.ID)
	flash := NewFlash("New pet was registered.", FlashLevelSuccess)
	d.SessionManager.Put(r.Context(), SessionKeyFlash, flash)
	redirectURL := strings.ReplaceAll(d.SuccessRedirectURL, "{pet_id}", pet.ID)
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

func (d *DoPetPostHandler) RenderPageTemplate(w http.ResponseWriter, data PostPetPage) {
	err := d.PageTemplateRenderer.RenderPageTemplate(w, "post_pet.html", data)
	if err != nil {
		panic(err)
	}
}

type PetsHandler struct {
	Log                  *slog.Logger
	PageTemplateRenderer PageTemplateRenderer
	SessionManager       *scs.SessionManager
	PetFinderByLocation  interface {
		FindPetByLocation(context.Context, Coordinates, FindPetByLocationFilter) ([]FindPetByLocationResult, error)
	}
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

func (p *PetsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sessionUser := GetSessionUser(r.Context())

	query := PetSearchQuery{
		Location: r.FormValue("location"),
		Type:     r.FormValue("type"),
	}

	var results []FindPetByLocationResult
	if query.Location != "" {
		parsedLocation, err := ParseCoordinates(query.Location)
		if err != nil {
			p.Log.Debug("Coordinates is invaild.", "coordinates", query.Location)
			p.RenderPage(w, PetsPage{
				BasePage: BasePage{
					SessionUser: sessionUser,
				},
				FormError: "Location is invalid.",
				Query:     query,
			})
			return
		}

		var petType *PetType
		if query.Type != "any" && query.Type != "" {
			if query.Type != string(PetTypeCat) && query.Type != string(PetTypeDog) {
				p.Log.Debug("Type is invaild.", "coordinates", query.Location)
				p.RenderPage(w, PetsPage{
					BasePage: BasePage{
						SessionUser: sessionUser,
					},
					FormError: "Type is invalid.",
					Query:     query,
				})
				return
			}
			tmp := PetType(query.Type)
			petType = &tmp
		}

		results, err = p.PetFinderByLocation.FindPetByLocation(r.Context(), parsedLocation, FindPetByLocationFilter{
			Type: petType,
		})
		if err != nil {
			p.Log.Error("Unable to find pet by location.", "reason", err.Error())
			p.RenderPage(w, PetsPage{
				BasePage: BasePage{
					SessionUser: sessionUser,
				},
				Flash: NewFlash("Something went wrong. Please try again later.", FlashLevelError),
				Query: query,
			})
			return
		}
	}

	p.Log.Debug("Pet search by location successful.", "total_result", len(results))

	flash, _ := PopSessionFlash(p.SessionManager, r.Context())
	p.RenderPage(w, PetsPage{
		BasePage: BasePage{
			SessionUser: sessionUser,
		},
		Flash:   flash,
		Query:   query,
		Results: results,
	})
}

func (p *PetsHandler) RenderPage(w http.ResponseWriter, data PetsPage) {
	err := p.PageTemplateRenderer.RenderPageTemplate(w, "pets.html", data)
	if err != nil {
		panic("unable to execute index template: " + err.Error())
	}
}

type PetsPage struct {
	BasePage
	Flash     *Flash
	FormError string
	Query     PetSearchQuery
	Results   []FindPetByLocationResult
}

type PetSearchQuery struct {
	Location string
	Type     string
}

type PetByIDHandler struct {
	Log                  *slog.Logger
	PageTemplateRenderer PageTemplateRenderer
	SessionManager       *scs.SessionManager
	NotFoundHandler      http.Handler
	PetGetter            interface {
		GetPetByID(ctx context.Context, petID string) (*Pet, error)
	}
	ShelterGetter interface {
		GetShelterByID(ctx context.Context, shelterID string) (*Shelter, error)
	}
}

var ErrNoPet = errors.New("pet not found")

func (p *PetByIDHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	userSession, _ := p.SessionManager.Get(r.Context(), SessionKeyUser).(*SessionUser)
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

	err = p.PageTemplateRenderer.RenderPageTemplate(w, "pet_by_id.html", PetByIDPage{
		BasePage: BasePage{
			SessionUser: userSession,
		},
		Flash:   flash,
		Shelter: shelter,
		Pet:     pet,
	})
	if err != nil {
		panic(err)
	}
}

type PetByIDPage struct {
	BasePage
	Flash   *Flash
	Pet     *Pet
	Shelter *Shelter
}
