package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/starryapi/starryapi/internal/server"
	"github.com/starryapi/starryapi/internal/store"
)

func main() {
	adminToken := os.Getenv("ADMIN_TOKEN")
	if len(adminToken) < 32 {
		log.Fatal("ADMIN_TOKEN must contain at least 32 characters")
	}
	path := os.Getenv("STORE_PATH")
	if path == "" {
		path = "./data/state.json"
	}
	s, err := store.Open(path)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	addr := os.Getenv("ADDR")
	if addr == "" {
		addr = ":8080"
	}
	h := &http.Server{
		Addr:              addr,
		Handler:           server.New(s, adminToken),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       90 * time.Second,
	}
	log.Printf("StarryAPI listening on %s", addr)
	log.Fatal(h.ListenAndServe())
}
