package authentication

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	u "net/url"

	"github.com/Nerzal/gocloak/v7"
	"github.com/golang-jwt/jwt/v4"
	"github.com/microsoft/kiota-abstractions-go/authentication"
)

type Credentials struct {
	AccessToken  string
	RefreshToken string
}

type RHAccessTokenProvider struct {
	credentials  Credentials
	allowedHosts []string
}

func (r *RHAccessTokenProvider) GetAuthorizationToken(context context.Context, url *u.URL, additionalAuthenticationContext map[string]interface{}) (string, error) {

	isAccessTokenValid, err := IsValid(r.credentials.AccessToken)
	if err != nil {
		return "", err
	}

	if isAccessTokenValid {
		return r.credentials.AccessToken, nil
	}

	tokens, err := RefreshTokens(r.credentials)
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

	credentials := Credentials{
		AccessToken:  tokens["access-token"],
		RefreshToken: tokens["refresh-token"],
	}

	RHAS := RHAccessTokenProvider{
		credentials:  credentials,
		allowedHosts: allowedHosts,
	}

	return RHAS
}

// NeedsRefresh checks if the access token is missing,
// expired or nearing expiry and should be refreshed
func needsRefresh(c Credentials) bool {
	if c.AccessToken == "" && c.RefreshToken != "" {
		return true
	}

	now := time.Now()
	expires, left, err := GetExpiry(c.AccessToken, now)
	if err != nil {
		return false
	}

	if !expires || left > 5*time.Minute {
		return false
	}

	return true
}

func GetExpiry(tokenStr string, now time.Time) (expires bool,
	left time.Duration, err error) {
	if tokenStr == "" {
		return true, 0, nil
	}
	token, err := Parse(tokenStr)
	if err != nil {
		return false, 0, err
	}

	claims, err := MapClaims(token)
	if err != nil {
		return false, 0, err
	}
	var exp float64
	claim, ok := claims["exp"]
	if ok {
		exp, ok = claim.(float64)
		if !ok {
			err = fmt.Errorf("expected floating point \"exp\" but got \"%v\"", claim)
			return
		}
	}
	if exp == 0 {
		expires = false
		left = 0
	} else {
		expires = true
		left = time.Unix(int64(exp), 0).Sub(now)
	}

	return
}

func Parse(textToken string) (token *jwt.Token, err error) {
	parser := new(jwt.Parser)
	token, _, err = parser.ParseUnverified(textToken, jwt.MapClaims{})
	if err != nil {
		err = fmt.Errorf("%v: %w", "unable to parse token", err)
		return
	}
	return token, nil
}

func MapClaims(token *jwt.Token) (claims jwt.MapClaims, err error) {
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		err = fmt.Errorf("expected map claims but got \"%v\"", claims)
	}

	return claims, err
}

func IsValid(token string) (tokenIsValid bool, err error) {
	now := time.Now()
	if token != "" {
		var expires bool
		var left time.Duration
		expires, left, err = GetExpiry(token, now)
		if err != nil {
			return
		}
		if !expires || left > 5*time.Second {
			tokenIsValid = true
			return
		}
	}
	return
}

// RefreshTokens will fetch a refreshed copy of the access token and refresh token from the authentication server
// The new tokens will have an increased expiry time and are persisted in the config and connection
func RefreshTokens(tokens Credentials) (refreshedTokens *Credentials, err error) {

	baseAuthURL := "http://localhost:8090"

	keycloak := gocloak.NewClient(baseAuthURL)
	restyClient := *keycloak.RestyClient()
	// #nosec 402
	restyClient.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	keycloak.SetRestyClient(&restyClient)

	// c.logger.Debug("Refreshing tokens")
	// nolint:govet
	refreshedTk, err := keycloak.RefreshToken(context.Background(), tokens.RefreshToken, "apicurio-client", "", "apicurio-local")
	if err != nil {
		return nil, err
	}

	if refreshedTk.AccessToken != tokens.AccessToken {
		refreshedTokens.AccessToken = refreshedTk.AccessToken
	}
	if refreshedTk.RefreshToken != tokens.RefreshToken {
		refreshedTokens.RefreshToken = refreshedTk.RefreshToken
	}

	return refreshedTokens, err
}
