package kiotaextra

import (
	"context"
	"crypto/tls"

	"github.com/Nerzal/gocloak/v7"
	"github.com/microsoft/kiota-abstractions-go/authentication"
	"github.com/rkpattnaik780/rh-kiota-go-auth/util"

	u "net/url"
)

type RHAccessTokenProvider struct {
	Credentials  util.Credentials
	AllowedHosts []string
	ClientID     string
	ClientSecret string
	RealmName    string
	BaseAuthURL  string
}

func (r RHAccessTokenProvider) GetAuthorizationToken(context context.Context, url *u.URL, additionalAuthenticationContext map[string]interface{}) (string, error) {

	isAccessTokenValid, err := util.IsValid(r.Credentials.AccessToken)
	if err != nil {
		return "", err
	}

	if isAccessTokenValid {
		return r.Credentials.AccessToken, nil
	}

	tokens, err := r.RefreshTokens()
	if err != nil {
		return "", err
	}

	return tokens.AccessToken, nil
}

// GetAllowedHostsValidator returns list of allowed hosts
func (r RHAccessTokenProvider) GetAllowedHostsValidator() *authentication.AllowedHostsValidator {

	allowedHostsValidator := authentication.NewAllowedHostsValidator(r.AllowedHosts)

	return &allowedHostsValidator

}

func NewRHAccessTokenProvider(tokens map[string]string, allowedHosts []string) RHAccessTokenProvider {

	credentials := util.Credentials{
		AccessToken:  tokens["access-token"],
		RefreshToken: tokens["refresh-token"],
	}

	RHAS := RHAccessTokenProvider{
		Credentials:  credentials,
		AllowedHosts: allowedHosts,
	}

	return RHAS
}

func (r RHAccessTokenProvider) RefreshTokens() (*util.Credentials, error) {

	keycloak := gocloak.NewClient(r.BaseAuthURL)
	restyClient := *keycloak.RestyClient()
	// #nosec 402
	restyClient.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	keycloak.SetRestyClient(&restyClient)

	refreshedTk, err := keycloak.RefreshToken(context.Background(), r.Credentials.RefreshToken, r.ClientID, r.ClientSecret, r.RealmName)
	if err != nil {
		return nil, err
	}

	refreshedTokens := &util.Credentials{
		RefreshToken: refreshedTk.RefreshToken,
		AccessToken:  refreshedTk.AccessToken,
	}

	return refreshedTokens, nil

}
