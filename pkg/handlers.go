package pkg

import (
	"net/http"
	"github.com/gorilla/sessions"
	log "github.com/getwhale/contrib/logging"
	"fmt"
	"encoding/base64"
	"errors"
	"github.com/gorilla/securecookie"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"time"
)


type Handlers struct {
	sessionCookieName string
	secretKey []byte
	cookieStore *sessions.CookieStore
	apiURL string
	token string
}

type tokenVerify struct {
	Token string `json:"token"`
}

func NewHandlers(secretKey []byte, sessionCookieName string, apiUrl string, token string) (*Handlers, error) {
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
		},
	}
	cs.MaxAge(cs.Options.MaxAge)
	handlers.cookieStore = cs

	return &handlers, nil
}

func (h *Handlers) authenticate(w http.ResponseWriter, r *http.Request) {
	log.Info("handling authenticate request")

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

	if token == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
}

func (h *Handlers) signIn(w http.ResponseWriter, r *http.Request) {
	log.Info("handling sign-in request")

	session, err := h.cookieStore.Get(r, h.sessionCookieName)
	if err != nil {
		log.Info("Could not read cookie", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	rd := r.FormValue("rd")
	if rd == "" {
		log.Info("Could not get redirect", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	token := r.FormValue("token")

	if token == "" {
		log.Info("no sign-in request, redirecting to login")

		/*
		 * Auth payload format
		 * proxy;signature_of_redirect;redirect
		 */

		mac := hmac.New(sha256.New, []byte(h.token))
		mac.Write([]byte(rd))

		data := fmt.Sprintf("%s;%s;%s", "1", hex.EncodeToString(mac.Sum(nil)), rd)
		encoding := base64.URLEncoding.EncodeToString([]byte(data))
		redirectURL := fmt.Sprintf("%s/auth-proxy/%s", h.apiURL, encoding)

		http.Redirect(w, r, redirectURL, http.StatusFound)
	} else {
		log.Info("got access token, storing session")

		client := &http.Client{
			Timeout: time.Second * 15,
		}
		url := fmt.Sprintf("%s/authproxy-verify", removeLastSlash(h.apiURL))
		payload := tokenVerify{
			Token: token,
		}
		request := createRequest(url, h.token, payload)
		response, err := client.Do(request)
		if err != nil {
			log.Info("Could not verify token", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		if response.StatusCode != 200 {
			log.Info("Invalid token")
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		session.Values["token"] = token
		err = session.Save(r, w)
		if err != nil {
			log.Error(err)
		}

		log.Info("redirect url", rd)
		http.Redirect(w, r, rd, http.StatusFound)
	}

}