package pkg

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

type State struct {
	Redirect string `json:"redirect"`
	SiteID   string `json:"siteID"`
	Checksum string `json:"checksum"`
}

// EncodeState creates a serializable payload that can be used to validate
// the oauth state for each client.
func EncodeState(secret []byte, redirect, siteID string) string {
	mac := hmac.New(sha256.New, secret)
	message := []byte(fmt.Sprintf("%s%s", redirect, siteID))
	mac.Write(message)

	state := State{
		Redirect: redirect,
		SiteID:   siteID,
		Checksum: base64.URLEncoding.EncodeToString(mac.Sum(nil)),
	}

	j, _ := json.Marshal(state)
	return base64.URLEncoding.EncodeToString(j)
}

// DecodeState verifies the state received from the oauth server and returns
// the state payload.
func DecodeState(secret []byte, stateParam string) (State, bool) {
	var state State
	stateBytes, err := base64.URLEncoding.DecodeString(stateParam)
	if err != nil {
		return state, false
	}

	err = json.Unmarshal(stateBytes, &state)
	if err != nil {
		return state, false
	}

	mac := hmac.New(sha256.New, secret)
	message := []byte(fmt.Sprintf("%s%s", state.Redirect, state.SiteID))
	mac.Write(message)

	stateMacBytes, err := base64.URLEncoding.DecodeString(state.Checksum)
	if err != nil {
		return state, false
	}

	valid := hmac.Equal(mac.Sum(nil), stateMacBytes)
	return state, valid
}

type CompleteState struct {
	Redirect string `json:"redirect"`
	UserID   string `json:"userId"`
}

func EncryptCompleteState(secret []byte, redirect, userID string) (string, error) {
	block, err := aes.NewCipher(secret)
	if err != nil {
		panic(err)
	}

	state := CompleteState{
		Redirect: redirect,
		UserID:   userID,
	}

	j, _ := json.Marshal(state)

	ciphertext := make([]byte, aes.BlockSize+len(j))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], j)

	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

func DecryptCompleteState(secret []byte, payload string) (CompleteState, error) {
	var state CompleteState

	ciphertext, _ := base64.URLEncoding.DecodeString(payload)

	block, err := aes.NewCipher(secret)
	if err != nil {
		return state, err
	}

	if len(ciphertext) < aes.BlockSize {
		return state, errors.New("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)

	stream.XORKeyStream(ciphertext, ciphertext)

	err = json.Unmarshal(ciphertext, &state)
	if err != nil {
		return state, err
	}

	return state, nil
}
