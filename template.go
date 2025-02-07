package main

import (
	"fmt"
	"io"
	"io/fs"
	"strings"
	"html/template"
	"time"
)

type PageRenderer interface {
	RenderPage(w io.Writer, page string, data any) error
}

type FSPageRenderer struct {
	FS    fs.FS
	cache map[string]*template.Template
}

func NewFSPageRenderer(fs fs.FS) *FSPageRenderer {
	return &FSPageRenderer{
		FS:    fs,
		cache: make(map[string]*template.Template),
	}
}

func (f *FSPageRenderer) RenderPage(w io.Writer, page string, data any) error {
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
			return fmt.Errorf("failed to parse %v page: %w", page, err)
		}

		f.cache[page] = tpl
	}

	err := ExecuteTemplate(tpl, w, "base.html", data)
	if err != nil {
		return fmt.Errorf("failed to execute %v page: %w", page, err)
	}

	return nil
}

const year = time.Hour * 24 * 365
const month = time.Hour * 24 * 30

func calculateAge(t time.Time) string {
	var results []string
	age := time.Now().Sub(t)

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
