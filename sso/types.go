package sso

import "github.com/justindh/gocrest/evetime"

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
