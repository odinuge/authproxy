package pkg

import (
	"net/http"
	"encoding/json"
	"bytes"
	"fmt"
)

func removeLastSlash(url string) string {
	l := len(url)
	if l > 0 && url[l-1] == '/' {
		return url[:l-2]
	}
	return url
}

func createRequest(url, token string, payload interface{}) *http.Request {
	j, _:= json.Marshal(payload)
	request, _ := http.NewRequest("POST", url, bytes.NewReader(j))
	request.Header.Add("AUTHORIZATION", fmt.Sprintf("Application %s", token))
	request.Header.Add("CONTENT-TYPE", "application/json")
	return request
}