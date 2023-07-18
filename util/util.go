package util

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type Credentials struct {
	AccessToken  string
	RefreshToken string
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
