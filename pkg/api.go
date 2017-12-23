package pkg

import (
	"bytes"
	"encoding/json"
	"fmt"
	log "github.com/getwhale/contrib/logging"
	"github.com/patrickmn/go-cache"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type API struct {
	apiUrl string
	client *http.Client
	cache  *cache.Cache
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
	logger := log.WithFields(log.Fields{"component": "api"})
	u, err := url.Parse(originalURL)
	if err != nil {
		logger.Warn("Unable to parse redirect url")
		return false, err
	}

	host := strings.ToLower(u.Host)

	cacheKey := fmt.Sprintf("%s-%s", accessToken, host)
	cached, found := a.cache.Get(cacheKey)
	if found {
		logger.Info("Using cached value")
		return cached.(bool), nil
	}

	logger.Info("No cache found, fetching access from whale")
	payload := authorizePaylaod{
		Resource: host,
	}
	var authorized bool

	apiURL := fmt.Sprintf("%s/authproxy-daemon/authorize", a.apiUrl)
	j, _ := json.Marshal(payload)
	request, _ := http.NewRequest("POST", apiURL, bytes.NewReader(j))
	request.Header.Add("AUTHORIZATION", fmt.Sprintf("Bearer %s", accessToken))
	request.Header.Add("CONTENT-TYPE", "application/json")
	response, err := a.client.Do(request)

	if err == nil && response.StatusCode == 200 {
		logger.WithFields(log.Fields{
			"statusCode": response.StatusCode,
			"host":       host,
		}).Info("Access granted by whale")
		authorized = true
		a.cache.Set(cacheKey, authorized, cache.DefaultExpiration)
		return authorized, nil
	}

	logger.WithFields(log.Fields{
		"statusCode": response.StatusCode,
		"error":      err,
		"host":       host,
	}).Info("Access denied by whale")
	return authorized, err
}
