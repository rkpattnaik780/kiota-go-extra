package kiotaextra

import (
	"context"

	"github.com/microsoft/kiota-abstractions-go/authentication"
	"github.com/rkpattnaik780/rh-kiota-go-auth/util"

	u "net/url"
)

type RHAccessTokenProvider struct {
	credentials  util.Credentials
	allowedHosts []string
}

func (r *RHAccessTokenProvider) GetAuthorizationToken(context context.Context, url *u.URL, additionalAuthenticationContext map[string]interface{}) (string, error) {

	isAccessTokenValid, err := util.IsValid(r.credentials.AccessToken)
	if err != nil {
		return "", err
	}

	if isAccessTokenValid {
		return r.credentials.AccessToken, nil
	}

	tokens, err := util.RefreshTokens(r.credentials)
	if err != nil {
		return "", err
	}

	return tokens.AccessToken, nil
}

// GetAllowedHostsValidator returns list of allowed hosts
func (r *RHAccessTokenProvider) GetAllowedHostsValidator() *authentication.AllowedHostsValidator {

	allowedHostsValidator := authentication.NewAllowedHostsValidator(r.allowedHosts)

	return &allowedHostsValidator

}

func NewRHAccessTokenProvider(tokens map[string]string, allowedHosts []string) RHAccessTokenProvider {

	credentials := util.Credentials{
		AccessToken:  tokens["access-token"],
		RefreshToken: tokens["refresh-token"],
	}

	RHAS := RHAccessTokenProvider{
		credentials:  credentials,
		allowedHosts: allowedHosts,
	}

	return RHAS
}
