package main

import (
	"time"
)

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

type Pet struct {
	ID           string
	Name         string
	Gender       Gender
	Type         PetType
	Images       []Image
	Description  string
	RegisteredAt time.Time
	UpdatedAt    time.Time
}
