package web

import (
	"embed"
	"html/template"
	"io/fs"
)

//go:embed templates/* static/*
var Assets embed.FS

// GetTemplateFS returns the embedded template filesystem
func GetTemplateFS() fs.FS {
	templates, _ := fs.Sub(Assets, "templates")
	return templates
}

// GetStaticFS returns the embedded static filesystem
func GetStaticFS() fs.FS {
	static, _ := fs.Sub(Assets, "static")
	return static
}

// LoadTemplates loads all HTML templates from embedded filesystem
func LoadTemplates() *template.Template {
	tmpl := template.New("")

	// Parse all template files
	templateFiles, err := fs.Glob(Assets, "templates/*.html")
	if err != nil {
		panic(err)
	}

	for _, file := range templateFiles {
		content, err := fs.ReadFile(Assets, file)
		if err != nil {
			panic(err)
		}

		name := file[len("templates/"):]
		_, err = tmpl.New(name).Parse(string(content))
		if err != nil {
			panic(err)
		}
	}

	return tmpl
}
