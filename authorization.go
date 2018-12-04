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
	// AuthorizerType is TODO
	AuthorizerType string

	// Authorizer is TODO
	Authorizer struct {
		Type                 AuthorizerType
		Realm                string
		Service              string
		Issuer               string
		BasicAuthMatchHeader string
		PublicKey            *rsa.PublicKey
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
		PublicCertPath   string
		AnonymousActions []string
	}

	// Permission is TODO
	Permission struct {
		Allowed               bool
		WWWAuthenticateHeader string
	}
)

// NewAuthorizer is TODO
func NewAuthorizer(opts *AuthorizerOptions) (*Authorizer, error) {
	authorizer := Authorizer{
		Realm:            opts.Realm,
		AnonymousActions: opts.AnonymousActions,
	}

	if opts.Username != "" && opts.Password != "" {

		// Basic
		authorizer.Type = BasicAuthAuthorizerType
		authorizer.BasicAuthMatchHeader = generateBasicAuthHeader(opts.Username, opts.Password)

	} else {

		// Bearer
		authorizer.Type = BearerAuthAuthorizerType
		authorizer.Service = opts.Service
		authorizer.Issuer = opts.Issuer

		publicKey, err := generatePublicKey(opts.PublicCertPath, opts.PublicCert)
		if err != nil {
			return nil, err
		}

		authorizer.PublicKey = publicKey
	}

	return &authorizer, nil
}

func (authorizer *Authorizer) Authorize(authHeader string, action string, namespace string) (*Permission, error) {
	if containsAction(authorizer.AnonymousActions, action) {

		// This specific action allowed anonymously
		return &Permission{Allowed: true}, nil

	} else if authorizer.Type == BasicAuthAuthorizerType {

		// Basic
		return authorizer.authorizeBasicAuth(authHeader)

	} else if authorizer.Type == BearerAuthAuthorizerType {

		// Bearer
		return authorizer.authorizeBearerAuth(authHeader, action, namespace)
	}

	return nil, errors.New(fmt.Sprintf("unknown authorizer type: %s", authorizer.Type))
}

func (authorizer *Authorizer) authorizeBasicAuth(authHeader string) (*Permission, error) {
	var allowed bool
	var wwwAuthenticateHeader string

	if authHeader == authorizer.BasicAuthMatchHeader {
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

func (authorizer *Authorizer) authorizeBearerAuth(authHeader string, action string, namespace string) (*Permission, error) {
	var allowed bool
	var wwwAuthenticateHeader string

	authHeader = strings.TrimPrefix(authHeader, "Bearer ")
	_, err := validateJWT(authHeader, authorizer.PublicKey)
	if err != nil {
		// TODO log/enumerate error
		wwwAuthenticateHeader = "Bearer realm=\"" + authorizer.Realm + "\""
	} else {
		// TODO inspect claims
		allowed = true
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

func generatePublicKey(publicCertPath string, publicCert []byte) (*rsa.PublicKey, error) {
	var pem []byte

	if publicCertPath != "" {
		var err error
		pem, err = ioutil.ReadFile(publicCertPath)
		if err != nil {
			return nil, err
		}
	} else if publicCert != nil {
		pem = publicCert
	} else {
		return nil, errors.New("Must supply either PublicCertPath or PublicCert")
	}

	// https://github.com/dgrijalva/jwt-go/blob/master/rsa_test.go
	return jwt.ParseRSAPublicKeyFromPEM(pem)
}

func generateBasicAuthHeader(username string, password string) string {
	base := username + ":" + password
	basicAuthHeader := "Basic " + base64.StdEncoding.EncodeToString([]byte(base))
	return basicAuthHeader
}

// verify if JWT is valid by using the rsa public certificate pem
// currently this only works with RSA key signing
// TODO: how best to handle many different signing algorithms?
func validateJWT(t string, key *rsa.PublicKey) (*jwt.Token, error) {
	token, err := jwt.Parse(t, func(token *jwt.Token) (interface{}, error) {
		return key, nil
	})
	if err != nil {
		return nil, err
	}

	return token, nil
}
