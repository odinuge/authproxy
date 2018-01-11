package pkg

import (
	"bytes"
	"encoding/json"
	"fmt"
	log "github.com/getwhale/contrib/logging"
	"github.com/patrickmn/go-cache"
	"io/ioutil"
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

type authResponse struct {
	URL string `json:"url"`
}

type cachePayload struct {
	Access bool
	URL    string
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

func (a *API) authorize(accessToken, siteId string) (bool, string, error) {
	logger := log.WithFields(log.Fields{"component": "api"})

	cacheKey := fmt.Sprintf("%s-%s", accessToken, siteId)
	cached, found := a.cache.Get(cacheKey)
	if found {
		logger.Info("Using cached value")
		payload := cached.(cachePayload)
		return payload.Access, payload.URL, nil
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

			body, err := ioutil.ReadAll(response.Body)
			if err != nil {
				log.Info("Could not read response from gate")
				return false, "", err
			}

			var data authResponse
			json.Unmarshal(body, &data)

			cacheData := cachePayload{
				Access: authorized,
				URL:    data.URL,
			}
			a.cache.Set(cacheKey, cacheData, cache.DefaultExpiration)
			return authorized, data.URL, nil
		}
	}

	logger.WithFields(log.Fields{
		"error":  err,
		"siteId": siteId,
	}).Info("Access denied by whale")
	return authorized, "", err
}
