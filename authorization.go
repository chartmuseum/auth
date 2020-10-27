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
	"encoding/json"
	"fmt"
	"github.com/jmespath/go-jmespath"
	"github.com/pkg/errors"
	"reflect"
	"regexp"
	"strings"
)

const (
	PullAction = "pull"
	PushAction = "push"
)

var (
	DefaultNamespace = "repo"

	BasicAuthAuthorizerType  AuthorizerType = "basic"
	BearerAuthAuthorizerType AuthorizerType = "bearer"

	bearerTokenMatch = regexp.MustCompile("(?i)bearer (.*)")
)

type (
	// AuthorizerType is TODO
	AuthorizerType string

	// Authorizer is TODO
	Authorizer struct {
		Type                     AuthorizerType
		Realm                    string
		Service                  string
		BasicAuthMatchHeader     string
		TokenDecoder             *TokenDecoder
		AnonymousActions         []string
		AccessEntryType          string
		DefaultNamespace         string
		AllowedActionsSearchPath string
	}

	// BasicAuthAuthorizerOptions is TODO
	AuthorizerOptions struct {
		Realm                    string
		Service                  string
		Username                 string
		Password                 string
		PublicKey                []byte
		PublicKeyPath            string
		AnonymousActions         []string
		AccessEntryType          string
		DefaultNamespace         string
		EmptyDefaultNamespace    bool
		AllowedActionsSearchPath string
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

	if opts.AccessEntryType == "" {
		authorizer.AccessEntryType = AccessEntryType
	} else {
		authorizer.AccessEntryType = opts.AccessEntryType
	}

	if opts.EmptyDefaultNamespace {
		authorizer.DefaultNamespace = ""
	} else if opts.DefaultNamespace != "" {
		authorizer.DefaultNamespace = opts.DefaultNamespace
	} else {
		authorizer.DefaultNamespace = DefaultNamespace
	}

	if opts.AccessEntryType == "" {
		authorizer.AccessEntryType = AccessEntryType
	} else {
		authorizer.AccessEntryType = opts.AccessEntryType
	}

	if opts.AllowedActionsSearchPath == "" {
		authorizer.AllowedActionsSearchPath = AllowedActionsSearchPath
	} else {
		authorizer.AllowedActionsSearchPath = opts.AllowedActionsSearchPath
	}

	if opts.Username != "" && opts.Password != "" {

		// Basic
		authorizer.Type = BasicAuthAuthorizerType
		authorizer.BasicAuthMatchHeader = generateBasicAuthHeader(opts.Username, opts.Password)

	} else {

		// Bearer
		authorizer.Type = BearerAuthAuthorizerType
		authorizer.Service = opts.Service

		tokenDecoder, err := NewTokenDecoder(&TokenDecoderOptions{
			PublicKey:     opts.PublicKey,
			PublicKeyPath: opts.PublicKeyPath,
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

	if namespace == "" {
		namespace = authorizer.DefaultNamespace
	}

	signedString := bearerTokenMatch.ReplaceAllString(authHeader, "$1")

	// TODO log error
	token, err := authorizer.TokenDecoder.DecodeToken(signedString)
	if err == nil {
		byteData, err := json.Marshal(token.Claims)
		if err == nil {
			var data interface{}
			err := json.Unmarshal(byteData, &data)
			if err == nil {
				allowedActionsSearchPath := strings.ReplaceAll(strings.ReplaceAll(authorizer.AllowedActionsSearchPath, "$NAMESPACE", namespace), "$ACCESS_ENTRY_TYPE", authorizer.AccessEntryType)
				result, err := jmespath.Search(allowedActionsSearchPath, data)
				if err == nil {
					switch reflect.TypeOf(result).Kind() {
					case reflect.Slice:
						allowedActions := reflect.ValueOf(result)
						for i := 0; i < allowedActions.Len(); i++ {
							if fmt.Sprintf("%v", allowedActions.Index(i)) == action {
								allowed = true
								break
							}
						}
					}
				}
			}
		}
	}

	if !allowed {
		wwwAuthenticateHeader = fmt.Sprintf("Bearer realm=\"%s\",service=\"%s\",scope=\"%s:%s:%s\"",
			authorizer.Realm, authorizer.Service, authorizer.AccessEntryType, namespace, action)
	}

	permission := Permission{
		Allowed:               allowed,
		WWWAuthenticateHeader: wwwAuthenticateHeader,
	}

	return &permission, nil
}
