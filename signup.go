package main

import (
	"html/template"
	"io/fs"
	"net/http"
)

type SignupTemplateData struct {
	Values SignupTemplateDataValues 
	Errors SignupTemplateDataErrors
}

type SignupTemplateDataValues struct {
	DisplayName     string
	Email           string
	Password        string
	ConfirmPassword string
}

type SignupTemplateDataErrors struct {
	DisplayName     string
	Email           string
	Password        string
	ConfirmPassword string
}

type SignupHandler struct {
	TemplateFS fs.FS

	signupTemplateCache *template.Template
}

func (s *SignupHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.signupTemplateCache == nil {
		var err error
		s.signupTemplateCache, err = template.ParseFS(s.TemplateFS, "base.html", "signup.html")
		if err != nil {
			panic("unable to parse signup template: " + err.Error())
		}
	}
	err := ExecuteTemplate(s.signupTemplateCache, w, "base.html", SignupTemplateData{})
	if err != nil {
		panic("unable to execute signup template: " + err.Error())
	}
}
