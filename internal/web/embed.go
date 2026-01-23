package web

import (
	"embed"
	"io/fs"
)

//go:embed static/*
var Assets embed.FS

// GetStaticFS returns the embedded static filesystem rooted at "static"
func GetStaticFS() fs.FS {
	static, _ := fs.Sub(Assets, "static")
	return static
}

// GetSubFS returns a subdirectory of the static filesystem
func GetSubFS(path string) fs.FS {
	sub, _ := fs.Sub(Assets, "static/"+path)
	return sub
}
