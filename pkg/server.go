package pkg

import (
	"github.com/gorilla/mux"
	"net/http"
	"time"
)

type Server struct {
	CookieSecret []byte
	CookieName string
	ListenAddr string
	ApiURL string
	Token string
}

func (s *Server) Run() error {
	r := mux.NewRouter()

	handlers, err := NewHandlers(s.CookieSecret, s.CookieName, s.ApiURL, s.Token)
	if err != nil {
		return err
	}

	r.HandleFunc("/whale-auth/auth", handlers.authenticate).Methods("GET")
	r.HandleFunc("/whale-auth/sign-in", handlers.signIn).Methods("GET")

	srv := &http.Server{
		Handler:      r,
		Addr:         s.ListenAddr,
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	return srv.ListenAndServe()
}