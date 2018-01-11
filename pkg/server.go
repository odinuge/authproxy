package pkg

import (
	"github.com/getwhale/contrib/runtime"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"net/http"
	"time"
)

type Server struct {
	ServerURL        string
	CookieSecret     []byte
	CookieName       string
	ListenAddr       string
	OIDCIssuer       string
	OIDCClient       string
	OIDCClientSecret string
}

func (s *Server) Run() error {
	runtime.OptimizeRuntime()

	r := mux.NewRouter()

	handlers, err := NewHandlers(
		s.ServerURL,
		s.CookieSecret,
		s.CookieName,
		s.OIDCIssuer,
		s.OIDCClient,
		s.OIDCClientSecret,
	)
	if err != nil {
		return err
	}

	r.HandleFunc("/whale-auth/auth/{id:[0-9]+}", handlers.authenticate).Methods("GET")
	r.HandleFunc("/whale-auth/sign-in/{id:[0-9]+}", handlers.signIn).Methods("GET", "POST")
	r.HandleFunc("/whale-auth/sign-complete/{state}", handlers.signInComplete).Methods("GET")
	r.HandleFunc("/whale-auth/sign-out", handlers.signOut).Methods("GET")

	r.HandleFunc("/complete", handlers.complete).Methods("GET")
	r.HandleFunc("/healthz", handlers.health).Methods("GET")
	r.Handle("/metrics", promhttp.Handler())

	srv := &http.Server{
		Handler:      r,
		Addr:         s.ListenAddr,
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	return srv.ListenAndServe()
}
