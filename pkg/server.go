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
	OIDCIssuer string
	OIDCClient string
}

func (s *Server) Run() error {
	r := mux.NewRouter()

	handlers, err := NewHandlers(
		s.CookieSecret,
		s.CookieName,
		s.ApiURL,
		s.Token,
		s.OIDCIssuer,
		s.OIDCClient,
	)
	if err != nil {
		return err
	}

	r.HandleFunc("/whale-auth/auth", handlers.authenticate).Methods("GET")
	r.HandleFunc("/whale-auth/sign-in", handlers.signIn).Methods("GET", "POST")
	r.HandleFunc("/whale-auth/sign-out", handlers.signOut).Methods("GET")

	srv := &http.Server{
		Handler:      r,
		Addr:         s.ListenAddr,
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	return srv.ListenAndServe()
}