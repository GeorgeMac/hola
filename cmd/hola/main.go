package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/georgemac/hola/lib/auth"
	"github.com/georgemac/hola/lib/middleware"
	"github.com/georgemac/hola/lib/storage/yaml"
)

var (
	secretsPath string
)

func successHandler(w http.ResponseWriter, r *http.Request) {
	scopes, ok, err := auth.ScopesFromContext(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if ok {
		fmt.Fprintf(w, "scopes %q", scopes)
	}
}

func main() {
	flag.StringVar(&secretsPath, "secrets", "secrets.yml", "Location of the secrets yaml")
	flag.Parse()

	secrets, err := os.Open(secretsPath)
	if err != nil {
		log.Fatal(err)
	}

	storage := yaml.NewStorage()
	if err := storage.ReadFrom(secrets); err != nil {
		log.Fatal(err)
	}

	handler := http.HandlerFunc(successHandler)
	http.Handle("/api/auth", middleware.New(handler, auth.New(storage)))
	fmt.Println(storage.Identities)
	http.ListenAndServe(":4040", nil)
}
