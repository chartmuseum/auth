/*
Copyright The Helm Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package auth

import (
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"github.com/pkg/errors"
	"io/ioutil"
	"strings"

	"github.com/dgrijalva/jwt-go"
)

const (
	PullAction = "pull"
	PushAction = "push"
)

var (
	BasicAuthAuthorizerType  AuthorizerType = "basic"
	BearerAuthAuthorizerType AuthorizerType = "bearer"
)

type (
	AuthorizerType string

	// Authorizer is a generic interface for authorizers
	Authorizer struct {
		Type                 AuthorizerType
		Realm                string
		Service              string
		Issuer               string
		BasicAuthMatchHeader string
		PublicCert           []byte
		AnonymousActions     []string
	}

	// BasicAuthAuthorizerOptions is TODO
	AuthorizerOptions struct {
		Realm            string
		Service          string
		Issuer           string
		Username         string
		Password         string
		PublicCert       []byte
		PublicCertPath   []byte
		AnonymousActions []string
	}

	// Permission is TODO
	Permission struct {
		Allowed               bool
		WWWAuthenticateHeader string
	}
)

func NewAuthorizer(opts *AuthorizerOptions) (*Authorizer, error) {
	authorizer := Authorizer{
		Realm:            opts.Realm,
		AnonymousActions: opts.AnonymousActions,
	}

	if opts.Username != "" && opts.Password != "" {
		authorizer.Type = BasicAuthAuthorizerType
		authorizer.BasicAuthMatchHeader = generateBasicAuthHeader(opts.Username, opts.Password)
	} else {
		authorizer.Type = BearerAuthAuthorizerType
		authorizer.Service = opts.Service
		authorizer.Issuer = opts.Issuer
	}

	return &authorizer, nil
}

func (authorizer *Authorizer) Authorize(authHeader string, action string, repo string) (*Permission, error) {
	if authorizer.Type == BasicAuthAuthorizerType {
		return authorizer.authorizeBasicAuth(authHeader, action, repo)
	} else if authorizer.Type == BearerAuthAuthorizerType {
		return authorizer.authorizeBearerAuth(authHeader, action, repo)
	}
	return nil, errors.New(fmt.Sprintf("unknown authorizer type: %s", authorizer.Type))
}

func (authorizer *Authorizer) authorizeBasicAuth(authHeader string, action string, repo string) (*Permission, error) {
	var allowed bool
	var wwwAuthenticateHeader string

	if containsAction(authorizer.AnonymousActions, action) {
		allowed = true
	} else if authHeader == authorizer.BasicAuthMatchHeader {
		allowed = true
	} else {
		wwwAuthenticateHeader = fmt.Sprintf("Basic realm=\"%s\"", authorizer.Realm)
	}

	permission := Permission{
		Allowed:               allowed,
		WWWAuthenticateHeader: wwwAuthenticateHeader,
	}

	return &permission, nil
}

func (authorizer *Authorizer) authorizeBearerAuth(authHeader string, action string, repo string) (*Permission, error) {
	var allowed bool
	var wwwAuthenticateHeader string

	splitToken := strings.Split(authHeader, "Bearer ")
	_, isValid := validateJWT(splitToken[1], authorizer.PublicCert)
	if isValid {
		allowed = true
	} else {
		wwwAuthenticateHeader = "Bearer realm=\"" + authorizer.Realm + "\""
	}

	permission := Permission{
		Allowed:               allowed,
		WWWAuthenticateHeader: wwwAuthenticateHeader,
	}

	return &permission, nil
}

func containsAction(actionsList []string, action string) bool {
	for _, a := range actionsList {
		if a == action {
			return true
		}
	}
	return false
}

func generateBasicAuthHeader(username string, password string) string {
	base := username + ":" + password
	basicAuthHeader := "Basic " + base64.StdEncoding.EncodeToString([]byte(base))
	return basicAuthHeader
}

// verify if JWT is valid by using the rsa public certificate pem
// currently this only works with RSA key signing
// TODO: how best to handle many different signing algorithms?
func validateJWT(t string, publicCert []byte) (*jwt.Token, bool) {
	valid := false

	key, err := getRSAKey(publicCert)
	if err != nil {
		fmt.Println(err)
	}

	token, err := jwt.Parse(t, func(token *jwt.Token) (interface{}, error) {
		return key, nil
	})
	if err != nil {
		fmt.Println("Token parse error: ", err)
	} else {
		fmt.Println("token is valid")
		valid = true
	}
	return token, valid
}

// https://github.com/dgrijalva/jwt-go/blob/master/rsa_test.go
func getRSAKey(key []byte) (*rsa.PublicKey, error) {
	parsedKey, err := jwt.ParseRSAPublicKeyFromPEM(key)
	if err != nil {
		fmt.Println("error parsing RSA key from PEM: ", err)
	}

	return parsedKey, nil
}

// Load authorization server public pem file
// TODO: have this be fetched from a url instead of file
func loadPublicCertFromFile(certPath string) []byte {
	publicKey, err := ioutil.ReadFile(certPath)
	if err != nil {
		panic(err)
	}
	return publicKey
}
