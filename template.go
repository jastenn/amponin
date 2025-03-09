package main

import (
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"strings"
	"time"
)

type PageTemplateRenderer interface {
	RenderPageTemplate(w io.Writer, page string, data any) error
}

type FSPageTemplateRenderer struct {
	FS    fs.FS
	cache map[string]*template.Template
}

func NewFSPageTemplateRenderer(fs fs.FS) *FSPageTemplateRenderer {
	return &FSPageTemplateRenderer{
		FS:    fs,
		cache: make(map[string]*template.Template),
	}
}

func (f *FSPageTemplateRenderer) RenderPageTemplate(w io.Writer, page string, data any) error {
	tpl, ok := f.cache[page]
	if !ok {
		var err error
		tpl, err = template.New(page).
			Funcs(template.FuncMap{
				"calculate_age": calculateAge,
				"fmt_distance":  fmtDistance,
			}).
			ParseFS(f.FS, "base.html", page)
		if err != nil {
			return fmt.Errorf("failed to parse %v web page template: %w", page, err)
		}

		f.cache[page] = tpl
	}

	err := ExecuteTemplate(tpl, w, "base.html", data)
	if err != nil {
		return fmt.Errorf("failed to execute %v web page template: %w", page, err)
	}

	return nil
}

const year = time.Hour * 24 * 365
const month = time.Hour * 24 * 30

func calculateAge(t time.Time) string {
	var results []string
	age := time.Since(t)

	ageInYears := age / year
	if ageInYears == 1 {
		results = append(results, fmt.Sprintf("%d year", ageInYears))
	} else if ageInYears > 1 {
		results = append(results, fmt.Sprintf("%d years", ageInYears))
	}
	age = age % year

	ageInMonth := age / month
	if ageInMonth == 1 {
		results = append(results, fmt.Sprintf("%d month", ageInMonth))
	} else if ageInMonth > 1 {
		results = append(results, fmt.Sprintf("%d months", ageInMonth))
	}

	return strings.Join(results, " and ") + " old"

}

func fmtDistance(meters int) string {
	kilometer := float64(meters) / 1000

	return fmt.Sprintf("%.2f KM", kilometer)
}

type MailTemplateRenderer interface {
	RenderMailTemplate(w io.Writer, name string, header map[string]string, data any) error
}

type FSMailTemplateRenderer struct {
	FS    fs.FS
	cache map[string]*template.Template
}

func NewFSMailTemplateRenderer(fs fs.FS) *FSMailTemplateRenderer {
	return &FSMailTemplateRenderer{
		FS:    fs,
		cache: make(map[string]*template.Template),
	}
}

func (f *FSMailTemplateRenderer) RenderMailTemplate(w io.Writer, filename string, header map[string]string, data any) error {
	for k, v := range header {
		fmt.Fprintf(w, "%v: %v\n", k, v)
	}
	fmt.Fprint(w, "MIME-Version: 1.0\n")
	fmt.Fprint(w, "Content-Type: text/html; charset=UTF-8\n")
	fmt.Fprint(w, "\n")

	tpl, ok := f.cache[filename]
	if !ok {
		var err error
		tpl, err = template.ParseFS(f.FS, filename)
		if err != nil {
			return fmt.Errorf("failed to parse %v mail template: %w", filename, err)
		}

		f.cache[filename] = tpl
	}

	err := ExecuteTemplate(tpl, w, filename, data)
	if err != nil {
		return fmt.Errorf("failed to execute %v mail template: %w", filename, err)
	}

	return nil
}
