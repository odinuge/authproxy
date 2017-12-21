package pkg

import (
	"net/http"
	"time"
	"github.com/patrickmn/go-cache"
	"net/url"
	"strings"
	"fmt"
	"encoding/json"
	"bytes"
)

type API struct {
	apiUrl string
	client *http.Client
	cache *cache.Cache
}

type authorizePaylaod struct {
	Resource string `json:"resource"`
}

func NewAPI(apiURL string) *API {
	api := API{
		apiUrl: apiURL,
	}
	api.client = &http.Client{
		Timeout: time.Second * 10,
	}
	api.cache = cache.New(5*time.Minute, 10*time.Minute)
	return &api
}

func (a *API) authorize(accessToken, originalURL string) (bool, error) {
	u, err := url.Parse(originalURL)
	if err != nil {
		return false, err
	}

	host := strings.ToLower(u.Host)

	cacheKey := fmt.Sprintf("%s-%s", accessToken, host)
	cached, found := a.cache.Get(cacheKey)
	if found {
		return cached.(bool), nil
	}

	payload := authorizePaylaod{
		Resource: host,
	}
	var authorized bool

	apiURL := fmt.Sprintf("%s/authproxy-daemon/authorize", a.apiUrl)
	j, _:= json.Marshal(payload)
	request, _ := http.NewRequest("POST", apiURL, bytes.NewReader(j))
	request.Header.Add("AUTHORIZATION", fmt.Sprintf("Bearer %s", accessToken))
	request.Header.Add("CONTENT-TYPE", "application/json")
	response, err := a.client.Do(request)

	if err == nil && response.StatusCode == 200 {
		authorized = true
		a.cache.Set(cacheKey, authorized, cache.DefaultExpiration)
		return authorized, nil
	}

	return authorized, err
}