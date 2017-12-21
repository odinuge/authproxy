package pkg

import (
	"github.com/gorilla/mux"
	"net/http"
	"time"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Server struct {
	CookieSecret []byte
	CookieName string
	ListenAddr string
	OIDCIssuer string
	OIDCClient string
	OIDCClientSecret string
	WhalePermissions bool
}

func (s *Server) Run() error {
	r := mux.NewRouter()

	handlers, err := NewHandlers(
		s.CookieSecret,
		s.CookieName,
		s.OIDCIssuer,
		s.OIDCClient,
		s.OIDCClientSecret,
		s.WhalePermissions,
	)
	if err != nil {
		return err
	}

	r.HandleFunc("/whale-auth/auth", handlers.authenticate).Methods("GET")
	r.HandleFunc("/whale-auth/sign-in", handlers.signIn).Methods("GET", "POST")
	r.HandleFunc("/whale-auth/complete", handlers.complete).Methods("GET")
	r.HandleFunc("/whale-auth/sign-out", handlers.signOut).Methods("GET")
	r.HandleFunc("/health", handlers.health).Methods("GET")

	r.Handle("/metrics", promhttp.Handler())

	srv := &http.Server{
		Handler:      r,
		Addr:         s.ListenAddr,
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	return srv.ListenAndServe()
}