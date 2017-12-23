package pkg

import (
	"context"
	"errors"
	"fmt"
	"github.com/coreos/go-oidc"
	log "github.com/getwhale/contrib/logging"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
	"net/http"
	"net/url"
)

type Handlers struct {
	sessionCookieName     string
	secretKey             []byte
	cookieStore           *sessions.CookieStore
	apiURL                string
	token                 string
	oauth2Config          *oauth2.Config
	tokenVerifier         *oidc.IDTokenVerifier
	checkWhalePermissions bool
	api                   *API
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
		secretKey:         secretKey,
	}

	cs := &sessions.CookieStore{
		Codecs: securecookie.CodecsFromPairs(secretKey),
		Options: &sessions.Options{
			Path:     "/",
			MaxAge:   86400,
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
		ClientID:     oidcClientID,
		ClientSecret: oidcClientSecret,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "authproxy"},
	}
	handlers.tokenVerifier = provider.Verifier(&oidc.Config{ClientID: oidcClientID})

	handlers.checkWhalePermissions = whalePermissions
	handlers.api = NewAPI(oidcIssuerUrl)

	return &handlers, nil
}

func createRedirectUrl(r string) string {
	u, err := url.Parse(r)
	if err != nil {
		return "http://127.0.0.1/whale-auth/complete"
	}
	return fmt.Sprintf("%s://%s/whale-auth/complete", u.Scheme, u.Host)
}

/**
 * Verify the token stored inside the session
 */
func (h *Handlers) authenticate(w http.ResponseWriter, r *http.Request) {
	logger := log.WithFields(log.Fields{"handler": "authenticate"})
	session, err := h.cookieStore.Get(r, h.sessionCookieName)
	if err != nil {
		logger.Warn("Could not read session")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	token, ok := session.Values["id_token"].(string)

	if !ok {
		logger.Info("No token in session")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	idToken, err := h.tokenVerifier.Verify(context.Background(), token)
	if err != nil {
		logger.Info("Invalid token in session")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var claims Claims
	err = idToken.Claims(&claims)
	if err != nil {
		logger.Info("Could not parse token claims")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if !h.checkWhalePermissions {
		logger.Info("Access granted without whale permissions")
		return
	}

	// Permissions check
	accessToken, ok := session.Values["access_token"].(string)
	if !ok {
		logger.Info("No access token")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	originalURL := r.Header.Get("X-ORIGINAL-URL")
	authorized, err := h.api.authorize(accessToken, originalURL)
	if !authorized || err != nil {
		logger.WithFields(log.Fields{"url": originalURL}).Info("Access denied by whale")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	logger.WithFields(log.Fields{"url": originalURL}).Info("Access granted")
}

/**
 * Redirecting to authorization server
 */
func (h *Handlers) signIn(w http.ResponseWriter, r *http.Request) {
	logger := log.WithFields(log.Fields{"handler": "sign-in"})
	rd := r.FormValue("rd")
	if rd == "" {
		logger.Warn("Cannot sign in without a redirect")
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	oauth2Config := new(oauth2.Config)
	*oauth2Config = *h.oauth2Config
	oauth2Config.RedirectURL = createRedirectUrl(rd)

	logger.Info("Initializing oauth2 redirect")
	http.Redirect(w, r, oauth2Config.AuthCodeURL(rd), http.StatusFound)
}

/**
 * Complete the openid authorization and store the token inside the session
 */
func (h *Handlers) complete(w http.ResponseWriter, r *http.Request) {
	logger := log.WithFields(log.Fields{"handler": "complete"})
	session, err := h.cookieStore.Get(r, h.sessionCookieName)
	if err != nil {
		logger.Warn("Cannot parse session")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	rd := r.URL.Query().Get("state")

	oauth2Config := new(oauth2.Config)
	*oauth2Config = *h.oauth2Config
	oauth2Config.RedirectURL = createRedirectUrl(rd)

	oauth2Token, err := oauth2Config.Exchange(context.Background(), r.URL.Query().Get("code"))
	if err != nil {
		logger.Info("Could not obtain token")
		http.Error(w, "Could not obtain token", http.StatusBadRequest)
		return
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		logger.Info("Token missing in response")
		http.Error(w, "Token is missing in response", http.StatusBadRequest)
		return
	}

	_, err = h.tokenVerifier.Verify(context.Background(), rawIDToken)
	if err != nil {
		logger.Info("Invalid token")
		http.Error(w, "Invalid token", http.StatusBadRequest)
		return
	}

	session.Values["id_token"] = rawIDToken
	session.Values["access_token"] = oauth2Token.AccessToken
	err = session.Save(r, w)
	if err != nil {
		logger.Warn("Unable to update session")
		http.Error(w, "Internal sever error", http.StatusInternalServerError)
		return
	}

	logger.Info("Session updated, redirecting to site")
	http.Redirect(w, r, rd, http.StatusFound)
}

/**
 * Clears the session and redirects to the sign-in page
 */
func (h *Handlers) signOut(w http.ResponseWriter, r *http.Request) {
	session, err := h.cookieStore.Get(r, h.sessionCookieName)
	if err != nil {
		log.WithFields(log.Fields{"handler": "sign-out"}).Warn("Unable to read session")
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
