package pkg

import (
	"net/http"
	"github.com/gorilla/sessions"
	log "github.com/getwhale/contrib/logging"
	"errors"
	"github.com/gorilla/securecookie"
	"github.com/coreos/go-oidc"
	"context"
	"text/template"
)


type Handlers struct {
	sessionCookieName string
	secretKey []byte
	cookieStore *sessions.CookieStore
	apiURL string
	token string
	tokenVerifier *oidc.IDTokenVerifier
}

type Claims struct {
	Groups []string `json:"groups"`
}

func NewHandlers(secretKey []byte, sessionCookieName, apiUrl, token, oidcIssuerUrl, oidcClientID string) (*Handlers, error) {
	if len(secretKey) < 32 {
		return nil, errors.New("secret key needs to have a length of at least 32")
	}

	handlers := Handlers{
		sessionCookieName: sessionCookieName,
		secretKey: secretKey,
		apiURL: apiUrl,
		token: token,
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
	handlers.tokenVerifier = provider.Verifier(&oidc.Config{ClientID: oidcClientID})

	return &handlers, nil
}

func (h *Handlers) authenticate(w http.ResponseWriter, r *http.Request) {
	session, err := h.cookieStore.Get(r, h.sessionCookieName)
	if err != nil {
		log.Info("Could not read cookie", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	token, ok := session.Values["token"].(string)
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

	// Permissions check
	log.Info(claims.Groups)
	log.Info(r.Header.Get("X-ORIGINAL-URL"))
}

func (h *Handlers) signIn(w http.ResponseWriter, r *http.Request) {
	session, err := h.cookieStore.Get(r, h.sessionCookieName)
	if err != nil {
		log.Info(err,"Could not read cookie")
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	rd := r.FormValue("rd")
	if rd == "" {
		log.Info(err, "Could not get redirect")
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	if r.Method == "POST" {
		token := r.FormValue("token")
		if token == "" {
			http.Error(w, "Invalid Token", http.StatusUnauthorized)
			return
		}

		_, err = h.tokenVerifier.Verify(context.Background(), token)
		if err != nil {
			http.Error(w, "Invalid Token", http.StatusUnauthorized)
			return
		}

		session.Values["token"] = token
		err = session.Save(r, w)
		if err != nil {
			log.Error(err)
		}

		http.Redirect(w, r, rd, http.StatusFound)
	} else {
		tmpl, err := template.New("test").Parse(LoginForm)
		if err != nil {
			panic(err)
		}
		err = tmpl.Execute(w, nil)
		if err != nil {
			panic(err)
		}
	}
}

/**
 * Clears the session and redirects to the sign-in page.
 */
func (h *Handlers) signOut(w http.ResponseWriter, r *http.Request) {
	session, err := h.cookieStore.Get(r, h.sessionCookieName)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
	session.Values["token"] = ""
	session.Options.MaxAge = -1
	session.Save(r, w)
	http.Redirect(w, r, "/", http.StatusFound)
}