package pkg

import (
	"bytes"
	"encoding/json"
	"fmt"
	log "github.com/getwhale/contrib/logging"
	"github.com/patrickmn/go-cache"
	"net/http"
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

func (a *API) authorize(accessToken, siteId string) (bool, error) {
	logger := log.WithFields(log.Fields{"component": "api"})

	cacheKey := fmt.Sprintf("%s-%s", accessToken, siteId)
	cached, found := a.cache.Get(cacheKey)
	if found {
		logger.Info("Using cached value")
		return cached.(bool), nil
	}

	logger.Info("No cache found, fetching access from whale")
	payload := authorizePaylaod{
		Resource: siteId,
	}
	var authorized bool

	apiURL := fmt.Sprintf("%s/authproxy-daemon/authorize", a.apiUrl)
	j, _ := json.Marshal(payload)
	request, _ := http.NewRequest("POST", apiURL, bytes.NewReader(j))
	request.Header.Add("AUTHORIZATION", fmt.Sprintf("Bearer %s", accessToken))
	request.Header.Add("CONTENT-TYPE", "application/json")
	request.Close = true
	response, err := a.client.Do(request)

	if err == nil {
		defer response.Body.Close()
		if response.StatusCode == 200 {
			logger.WithFields(log.Fields{
				"statusCode": response.StatusCode,
				"siteId":     siteId,
			}).Info("Access granted by whale")
			authorized = true
			a.cache.Set(cacheKey, authorized, cache.DefaultExpiration)
			return authorized, nil
		}
	}

	logger.WithFields(log.Fields{
		"error":  err,
		"siteId": siteId,
	}).Info("Access denied by whale")
	return authorized, err
}
