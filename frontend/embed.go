package web

import (
	"embed"
	"fmt"
	"io/fs"
)

//go:embed dist
var Assets embed.FS

// GetStaticFS returns the embedded static filesystem rooted at "dist"
func GetStaticFS() fs.FS {
	static, err := fs.Sub(Assets, "dist")
	if err != nil {
		panic(fmt.Sprintf("Failed to get static filesystem: %v. Make sure frontend is built first (run 'make frontend')", err))
	}
	return static
}

// GetSubFS returns a subdirectory of the static filesystem
func GetSubFS(path string) fs.FS {
	sub, err := fs.Sub(Assets, "dist/"+path)
	if err != nil {
		panic(fmt.Sprintf("Failed to get sub filesystem for '%s': %v", path, err))
	}
	return sub
}
