package pkg

import (
	"context"
	"errors"
	"fmt"
	"github.com/coreos/go-oidc"
	log "github.com/getwhale/contrib/logging"
	"github.com/getwhale/contrib/strings"
	"github.com/gorilla/mux"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
	"net/http"
	"net/url"
)

type Handlers struct {
	serverURL         string
	sessionCookieName string
	secretKey         []byte
	cookieStore       *sessions.CookieStore
	apiURL            string
	token             string
	oauth2Config      *oauth2.Config
	api               *API
}

type Claims struct{}

func NewHandlers(serverURL string, secretKey []byte, sessionCookieName, oidcIssuerUrl, oidcClientID, oidcClientSecret string) (*Handlers, error) {
	if len(secretKey) < 32 {
		return nil, errors.New("secret key needs to have a length of at least 32")
	}

	handlers := Handlers{
		serverURL:         serverURL,
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
		log.Fatal(err, "Could not create oidc provider")
	}
	handlers.oauth2Config = &oauth2.Config{
		ClientID:     oidcClientID,
		ClientSecret: oidcClientSecret,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "authproxy"},
	}

	handlers.api = NewAPI(oidcIssuerUrl)

	return &handlers, nil
}

func (h *Handlers) createRedirectUrl() string {
	return fmt.Sprintf("%s/complete", strings.RemoveLastSlash(h.serverURL))
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

	// Permissions check
	accessToken, ok := session.Values["access_token"].(string)
	if !ok {
		logger.Info("Could not retrieve access_token from session")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	siteId := mux.Vars(r)["id"]

	authorized, err := h.api.authorize(accessToken, siteId)
	if !authorized || err != nil {
		logger.WithFields(log.Fields{"siteId": siteId}).Info("Access denied by whale")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	logger.WithFields(log.Fields{"siteId": siteId}).Info("Access granted")
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
	oauth2Config.RedirectURL = h.createRedirectUrl()

	logger.Info("Initializing oauth2 redirect")

	siteID := mux.Vars(r)["id"]
	state := EncodeState(h.secretKey, rd, siteID)

	http.Redirect(w, r, oauth2Config.AuthCodeURL(state), http.StatusFound)
}

// Receive the encrypted secrets from the complete endpoint and update session.
func (h *Handlers) signInComplete(w http.ResponseWriter, r *http.Request) {
	logger := log.WithFields(log.Fields{"handler": "signInComplete"})
	session, err := h.cookieStore.Get(r, h.sessionCookieName)
	if err != nil {
		logger.Warn("Cannot parse session")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	vars := mux.Vars(r)
	state, err := DecryptCompleteState(h.secretKey, vars["state"])
	if err != nil {
		logger.Warn("Unable to read complete state")
		http.Error(w, "Internal sever error", http.StatusInternalServerError)
		return
	}

	session.Values["access_token"] = state.AccessToken

	err = session.Save(r, w)
	if err != nil {
		logger.Warn("Unable to update session")
		http.Error(w, "Internal sever error", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, state.Redirect, http.StatusFound)
}

/**
 * Complete the openid authorization and store the token inside the session
 */
func (h *Handlers) complete(w http.ResponseWriter, r *http.Request) {
	logger := log.WithFields(log.Fields{"handler": "complete"})

	stateParam := r.URL.Query().Get("state")
	state, ok := DecodeState(h.secretKey, stateParam)
	if !ok {
		logger.Info("Invalid state param")
		http.Error(w, "Invalid state param", http.StatusBadRequest)
		return
	}

	oauth2Config := new(oauth2.Config)
	*oauth2Config = *h.oauth2Config
	oauth2Config.RedirectURL = h.createRedirectUrl()

	oauth2Token, err := oauth2Config.Exchange(context.Background(), r.URL.Query().Get("code"))
	if err != nil {
		logger.Info("Could not obtain token")
		http.Error(w, "Could not obtain token", http.StatusBadRequest)
		return
	}

	authorized, err := h.api.authorize(oauth2Token.AccessToken, state.SiteID)
	if !authorized || err != nil {
		logger.WithFields(log.Fields{"siteId": state.SiteID}).Info("Access denied by whale")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	completeState, err := EncryptCompleteState(h.secretKey, state.Redirect, oauth2Token.AccessToken)
	if err != nil {
		logger.Info("Could not encrypt state")
		http.Error(w, "Invalid token", http.StatusBadRequest)
		return
	}

	redirect, err := url.Parse(state.Redirect)
	if err != nil {
		logger.Info("Cannot parse redirect url")
		http.Error(w, "Invalid redirect", http.StatusBadRequest)
		return
	}

	completeURL := fmt.Sprintf("%s://%s/whale-auth/sign-complete/%s", redirect.Scheme, redirect.Host, completeState)
	logger.WithFields(log.Fields{"redirect": completeURL}).Info("Session updated, redirecting to sign-in complete")
	http.Redirect(w, r, completeURL, http.StatusFound)
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
