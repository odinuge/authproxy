package pkg

import (
	"net/http"
	"github.com/gorilla/sessions"
	log "github.com/getwhale/contrib/logging"
	"errors"
	"github.com/gorilla/securecookie"
	"github.com/coreos/go-oidc"
	"context"
	"golang.org/x/oauth2"
)


type Handlers struct {
	sessionCookieName string
	secretKey []byte
	cookieStore *sessions.CookieStore
	apiURL string
	token string
	oauth2Config *oauth2.Config
	tokenVerifier *oidc.IDTokenVerifier
	checkWhalePermissions bool
	api *API
}

type Claims struct {
	Groups []string `json:"groups"`
}

func NewHandlers(secretKey []byte, sessionCookieName, oidcIssuerUrl, oidcClientID, oidcClientSecret string, whalePermissions bool) (*Handlers, error) {
	if len(secretKey) < 32 {
		return nil, errors.New("secret key needs to have a length of at least 32")
	}

	handlers := Handlers{
		sessionCookieName: sessionCookieName,
		secretKey: secretKey,
	}

	cs := &sessions.CookieStore{
		Codecs: securecookie.CodecsFromPairs(secretKey),
		Options: &sessions.Options{
			Path: "/",
			MaxAge: 86400,
			HttpOnly: true,
		},
	}
	cs.MaxAge(cs.Options.MaxAge)
	handlers.cookieStore = cs

	provider, err := oidc.NewProvider(context.Background(), oidcIssuerUrl)
	if err != nil {
		log.Fatal(err, "Could not create dex provider")
	}
	handlers.oauth2Config = &oauth2.Config{
		ClientID: oidcClientID,
		ClientSecret: oidcClientSecret,
		RedirectURL: "http://127.0.0.1:3000/whale-auth/complete",
		Endpoint: provider.Endpoint(),
		Scopes: []string{oidc.ScopeOpenID, "authproxy"},
	}
	handlers.tokenVerifier = provider.Verifier(&oidc.Config{ClientID: oidcClientID})

	handlers.checkWhalePermissions = whalePermissions
	handlers.api = NewAPI(oidcIssuerUrl)

	return &handlers, nil
}

/**
 * Verify the token stored inside the session
 */
func (h *Handlers) authenticate(w http.ResponseWriter, r *http.Request) {
	session, err := h.cookieStore.Get(r, h.sessionCookieName)
	if err != nil {
		log.Info("Could not read cookie", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	token, ok := session.Values["id_token"].(string)

	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	idToken, err := h.tokenVerifier.Verify(context.Background(), token)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var claims Claims
	err = idToken.Claims(&claims)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if !h.checkWhalePermissions {
		return
	}

	// Permissions check
	accessToken, ok := session.Values["access_token"].(string)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	originalURL := r.Header.Get("X-ORIGINAL-URL")
	authorized, err := h.api.authorize(accessToken, originalURL)
	if !authorized || err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
}

/**
 * Redirecting to authorization server
 */
func (h *Handlers) signIn(w http.ResponseWriter, r *http.Request) {
	rd := r.FormValue("rd")
	if rd == "" {
		log.Info("Could not get redirect")
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	http.Redirect(w, r, h.oauth2Config.AuthCodeURL(rd), http.StatusFound)
}

/**
 * Complete the openid authorization and store the token inside the session
 */
func (h *Handlers) complete(w http.ResponseWriter, r *http.Request) {
	session, err := h.cookieStore.Get(r, h.sessionCookieName)
	if err != nil {
		log.Info("Could not read cookie", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	oauth2Token, err := h.oauth2Config.Exchange(context.Background(), r.URL.Query().Get("code"))
	if err != nil {
		http.Error(w, "Could not obtain token", http.StatusBadRequest)
		return
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "Token is missing in response", http.StatusBadRequest)
		return
	}

	_, err = h.tokenVerifier.Verify(context.Background(), rawIDToken)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusBadRequest)
		return
	}

	session.Values["id_token"] = rawIDToken
	session.Values["access_token"] = oauth2Token.AccessToken
	err = session.Save(r, w)
	if err != nil {
		http.Error(w, "Internal sever error", http.StatusInternalServerError)
		return
	}

	rd := r.URL.Query().Get("state")
	http.Redirect(w, r, rd, http.StatusFound)
}

/**
 * Clears the session and redirects to the sign-in page
 */
func (h *Handlers) signOut(w http.ResponseWriter, r *http.Request) {
	session, err := h.cookieStore.Get(r, h.sessionCookieName)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	session.Values["token"] = ""
	session.Options.MaxAge = -1
	session.Save(r, w)
	http.Redirect(w, r, "/", http.StatusFound)
}

/**
 * Health endpoint
 */
func (h *Handlers) health(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}