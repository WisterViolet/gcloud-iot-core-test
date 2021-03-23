package iotcore

import (
	"io/ioutil"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

const (
	algorithm = "RS256"
)

func createJWT(projectID string, privateKeyPath string, expiration time.Duration) (string, error) {
	claims := jwt.StandardClaims{
		Audience:  projectID,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(expiration).Unix(),
	}

	keyBytes, err := ioutil.ReadFile(privateKeyPath)
	if err != nil {
		return "", err
	}

	token := jwt.NewWithClaims(jwt.GetSigningMethod(algorithm), claims)

	privkey, _ := jwt.ParseRSAPrivateKeyFromPEM(keyBytes)
	return token.SignedString(privkey)
}
