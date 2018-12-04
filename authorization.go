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
	"fmt"
	"github.com/pkg/errors"
	"strings"
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
		TokenDecoder         *TokenDecoder
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

		tokenDecoder, err := NewTokenDecoder(&TokenDecoderOptions{
			PublicCert:     opts.PublicCert,
			PublicCertPath: opts.PublicCertPath,
		})
		if err != nil {
			return nil, err
		}

		authorizer.TokenDecoder = tokenDecoder
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

	signedString := strings.TrimPrefix(authHeader, "Bearer ")

	// TODO log error
	token, err := authorizer.TokenDecoder.DecodeToken(signedString)
	if err == nil {

		// TODO log error
		claims, err := getTokenCustomClaims(token)
		if err == nil {
			for _, entry := range claims.Access {
				if entry.Type == DefaultAccessEntryType {
					if entry.Name == namespace {
						for _, act := range entry.Actions {
							if act == action {
								allowed = true
								break
							}
						}
					}
				}
				if allowed {
					break
				}
			}
		}
	}

	if !allowed {
		wwwAuthenticateHeader = "Bearer realm=\"" + authorizer.Realm + "\""
	}

	permission := Permission{
		Allowed:               allowed,
		WWWAuthenticateHeader: wwwAuthenticateHeader,
	}

	return &permission, nil
}
