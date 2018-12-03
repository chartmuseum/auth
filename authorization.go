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
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
)

type (
	// Router handles all incoming HTTP requests
	Router struct {
		BasicAuthHeader  string
		BearerAuthHeader string
		AnonymousGet     bool
		AuthRealm        string
		AuthService      string
		AuthIssuer       string
		AuthPublicCert   []byte
	}

	// Authorization is TODO
	Authorization struct {
		Authorized            bool
		WWWAuthenticateHeader string
	}

	// Authorizer is a generic interface for authorizers
	Authorizer interface {
		AuthorizeRequest(request *http.Request, action string, repo string) (*Authorization, error)
	}

	// BasicAuthAuthorizer is TODO
	BasicAuthAuthorizer struct {
		Realm                string
		BasicAuthMatchHeader string
		AnonymousActions     []string
	}

	// BasicAuthAuthorizerOptions is TODO
	BasicAuthAuthorizerOptions struct {
		Realm            string
		Username         string
		Password         string
		AnonymousActions []string
	}
)

func NewBasicAuthAuthorizer(opts *BasicAuthAuthorizerOptions) *BasicAuthAuthorizer {

	basicAuthAuthorizer := BasicAuthAuthorizer{
		Realm:                opts.Realm,
		BasicAuthMatchHeader: generateBasicAuthHeader(opts.Username, opts.Password),
		AnonymousActions:     opts.AnonymousActions,
	}
	return &basicAuthAuthorizer
}

func (authorizer *BasicAuthAuthorizer) AuthorizeRequest(request *http.Request, action string, repo string) (*Authorization, error) {
	var authorized bool
	var wwwAuthenticateHeader string

	if containsAction(authorizer.AnonymousActions, action) {
		authorized = true
	} else if request.Header.Get("Authorization") == authorizer.BasicAuthMatchHeader {
		authorized = true
	} else {
		wwwAuthenticateHeader = fmt.Sprintf("Basic realm=\"%s\"", authorizer.Realm)
	}

	authorization := Authorization{
		Authorized:            authorized,
		WWWAuthenticateHeader: wwwAuthenticateHeader,
	}

	return &authorization, nil
}

var (
	PullAction       = "pull"
	PushAction       = "push"
	SystemInfoAction = "sysinfo"
)

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

func (router *Router) authorizeRequest(request *http.Request) (bool, map[string]string) {
	authorized := false
	responseHeaders := map[string]string{}

	// BasicAuthHeader is only set on the router if ChartMuseum is configured to use
	// basic auth protection. If not set, the server and all its routes are wide open.
	if router.BasicAuthHeader != "" {
		if router.AnonymousGet && request.Method == "GET" {
			authorized = true
		} else if request.Header.Get("Authorization") == router.BasicAuthHeader {
			authorized = true
		} else {
			responseHeaders["WWW-Authenticate"] = "Basic realm=\"ChartMuseum\""
		}
	} else if router.BearerAuthHeader != "" {
		// used to escape spaces in service name
		queryString := url.PathEscape("service=" + router.AuthService)

		if router.AnonymousGet && request.Method == "GET" {
			authorized = true
		} else {
			if request.Header.Get("Authorization") != "" {
				splitToken := strings.Split(request.Header.Get("Authorization"), "Bearer ")
				_, isValid := validateJWT(splitToken[1], router)
				if isValid {
					authorized = true
				} else {
					responseHeaders["WWW-Authenticate"] = "Bearer realm=\"" + router.AuthRealm + "?" + queryString + "\""
				}
			} else {
				responseHeaders["WWW-Authenticate"] = "Bearer realm=\"" + router.AuthRealm + "?" + queryString + "\""
			}
		}
	} else {
		authorized = true
	}

	return authorized, responseHeaders
}

// verify if JWT is valid by using the rsa public certificate pem
// currently this only works with RSA key signing
// TODO: how best to handle many different signing algorithms?
func validateJWT(t string, router *Router) (*jwt.Token, bool) {
	valid := false

	key, err := getRSAKey(router.AuthPublicCert)
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
func loadPublicCertFromFile(certPath string, router *Router) {
	publicKey, err := ioutil.ReadFile(certPath)
	if err != nil {
		panic(err)
	}
	router.AuthPublicCert = publicKey
}
