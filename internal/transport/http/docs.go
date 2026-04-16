package httpserver

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed swagger swagger/* swagger/assets/*
var swaggerFS embed.FS

func swaggerHandler() http.Handler {
	sub, err := fs.Sub(swaggerFS, "swagger")
	if err != nil {
		panic(err)
	}

	fileServer := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Swagger UI serves local JS/CSS assets and uses inline bootstrapping code.
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:")
		fileServer.ServeHTTP(w, r)
	})
}
