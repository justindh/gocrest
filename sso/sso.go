package sso

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/justindh/gocrest/evetime"
)

const (
	PathOAuthAuthorize = "/oauth/authorize"
	PATHOAuthToken     = "/oauth/token"
	PATHOAuthVerify    = "/oauth/verify"
	TokenAuth          = "authorization_code"
	TokenRefresh       = "refresh_token"
)

type SSO struct {
	LoginURL    string
	CallbackURL string
	ClientID    string
	SecretKey   string
	UserAgent   string
	Scopes      []string
}

func NewSSO(loginURL, callbackURL, clientID, secretKey, userAgent string, scopes []string) SSO {
	return SSO{LoginURL: loginURL, CallbackURL: callbackURL, ClientID: clientID, SecretKey: secretKey, UserAgent: userAgent, Scopes: scopes}
}

func (s *SSO) Call(method, path string, args url.Values, output interface{}) error {
	uri := s.LoginURL + path
	if args == nil {
		args = url.Values{}
	}
	resp, err := http.NewRequest(method, uri, bytes.NewBufferString(args.Encode()))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	err = json.NewDecoder(resp.Body).Decode(&output)
	if err != nil {
		return err
	}
	return nil
}

func (s *SSO) CallRequest(request *http.Request, output interface{}) error {
	client := &http.Client{}
	resp, err := client.Do(request)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("Error: received %v status code return: %v", resp.StatusCode, string(respBytes[:]))
	}
	err = json.Unmarshal(respBytes, &output)
	if err != nil {
		return err
	}
	return nil
}

func (s *SSO) GetAuthURI(state string) (url.URL, error) {
	sURL, err := url.Parse(fmt.Sprintf("%s%s", s.LoginURL, PathOAuthAuthorize))
	if err != nil {
		return url.URL{}, err
	}
	params := url.Values{}
	params.Add("response_type", "code")
	params.Add("redirect_uri", s.CallbackURL)
	params.Add("client_id", s.ClientID)
	params.Add("scope", strings.Join(s.Scopes, " "))
	params.Add("state", state)
	sURL.RawQuery = params.Encode()
	return *sURL, nil
}

func (s *SSO) GetToken(code, grantType string) (OAuthTokenResponse, error) {
	oatr := OAuthTokenResponse{}
	jsondata := new(bytes.Buffer)
	json.NewEncoder(jsondata).Encode(OAuthVerify{GrantType: grantType, Code: code, RefreshToken: code})
	req, err := http.NewRequest("POST", fmt.Sprintf("%s%s", s.LoginURL, PATHOAuthToken), jsondata)
	if err != nil {
		return oatr, err
	}
	encodedKeys := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", s.ClientID, s.SecretKey)))
	req.Header.Set("Authorization", fmt.Sprintf("Basic %s", encodedKeys))
	req.Header.Set("Content-Type", "application/json")
	err = s.CallRequest(req, &oatr)
	return oatr, err
}

func (s *SSO) VerifyToken(token string) (OAuthVerifyReponse, error) {
	oavr := OAuthVerifyReponse{}
	req, err := http.NewRequest("GET", fmt.Sprintf("%s%s", s.LoginURL, PATHOAuthVerify), new(bytes.Buffer))
	if err != nil {
		return oavr, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	err = s.CallRequest(req, &oavr)
	return oavr, err
}

type OAuthVerify struct {
	GrantType    string `json:"grant_type"`
	Code         string `json:"code"`
	RefreshToken string `json:"refresh_token"`
}
type OAuthTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

type OAuthVerifyReponse struct {
	CharacterID        int             `json:"CharacterID"`
	CharacterName      string          `json:"CharacterName"`
	ExpiresOn          evetime.EveTime `json:"ExpiresOn"`
	Scopes             string          `json:"Scopes"`
	TokenType          string          `json:"TokenType"`
	CharacterOwnerHash string          `json:"CharacterOwnerHash"`
}
