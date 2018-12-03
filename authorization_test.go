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
	"net/http"
	"testing"

	"github.com/stretchr/testify/suite"
)

type AuthorizationTestSuite struct {
	suite.Suite
	BasicAuthAuthorizer              Authorizer
	BasicAuthAnonymousPullAuthorizer Authorizer
	BasicAuthAnonymousPushAuthorizer Authorizer
}

func (suite *AuthorizationTestSuite) SetupSuite() {
	suite.BasicAuthAuthorizer = Authorizer(NewBasicAuthAuthorizer(&BasicAuthAuthorizerOptions{
		Realm:        "cm-test-realm",
		Username:     "cm-test-user",
		Password:     "cm-test-pass",
		AnonymousActions: []string{},
	}))
	suite.BasicAuthAnonymousPullAuthorizer = Authorizer(NewBasicAuthAuthorizer(&BasicAuthAuthorizerOptions{
		Realm:        "cm-test-realm",
		Username:     "cm-test-user",
		Password:     "cm-test-pass",
		AnonymousActions: []string{PullAction},
	}))
	suite.BasicAuthAnonymousPushAuthorizer = Authorizer(NewBasicAuthAuthorizer(&BasicAuthAuthorizerOptions{
		Realm:        "cm-test-realm",
		Username:     "cm-test-user",
		Password:     "cm-test-pass",
		AnonymousActions: []string{PullAction, PushAction},
	}))
}

func (suite *AuthorizationTestSuite) TearDownSuite() {
	return
}

func (suite *AuthorizationTestSuite) TestAuthorizeRequest() {
	var req *http.Request
	var authorization *Authorization
	var err error

	badAuthorizationHeader := generateBasicAuthHeader("cm-test-baduser", "cm-test-badpass")
	goodAuthorizationHeader := generateBasicAuthHeader("cm-test-user", "cm-test-pass")

	expectedWWWAuthHeader := "Basic realm=\"cm-test-realm\""

	// No username/password
	req, _ = http.NewRequest(http.MethodGet, "/charts/mychart-0.1.0.tgz", nil)
	authorization, err = suite.BasicAuthAuthorizer.AuthorizeRequest(req, PullAction, "")
	suite.False(authorization.Authorized)
	suite.Equal(expectedWWWAuthHeader, authorization.WWWAuthenticateHeader)
	suite.Nil(err)

	// Bad username/password
	req, _ = http.NewRequest(http.MethodGet, "/charts/mychart-0.1.0.tgz", nil)
	req.Header.Set("Authorization", badAuthorizationHeader)
	authorization, err = suite.BasicAuthAuthorizer.AuthorizeRequest(req, PullAction, "")
	suite.False(authorization.Authorized)
	suite.Equal(expectedWWWAuthHeader, authorization.WWWAuthenticateHeader)
	suite.Nil(err)

	// Correct username/password
	req, _ = http.NewRequest(http.MethodGet, "/charts/mychart-0.1.0.tgz", nil)
	req.Header.Set("Authorization", goodAuthorizationHeader)
	authorization, err = suite.BasicAuthAuthorizer.AuthorizeRequest(req, PullAction, "")
	suite.True(authorization.Authorized)
	suite.Equal("", authorization.WWWAuthenticateHeader)
	suite.Nil(err)

	// Anonymous Pull, no username/password (GET/PullAction)
	req, _ = http.NewRequest(http.MethodGet, "/charts/mychart-0.1.0.tgz", nil)
	authorization, err = suite.BasicAuthAnonymousPullAuthorizer.AuthorizeRequest(req, PullAction, "")
	suite.True(authorization.Authorized)
	suite.Equal("", authorization.WWWAuthenticateHeader)
	suite.Nil(err)

	// Anonymous Pull, no username/password (POST/PushAction)
	req, _ = http.NewRequest(http.MethodPost, "/api/charts", nil)
	authorization, err = suite.BasicAuthAnonymousPullAuthorizer.AuthorizeRequest(req, PushAction, "")
	suite.False(authorization.Authorized)
	suite.Equal(expectedWWWAuthHeader, authorization.WWWAuthenticateHeader)
	suite.Nil(err)

	// Anonymous Push, no username/password (GET/PullAction)
	req, _ = http.NewRequest(http.MethodGet, "/charts/mychart-0.1.0.tgz", nil)
	authorization, err = suite.BasicAuthAnonymousPushAuthorizer.AuthorizeRequest(req, PullAction, "")
	suite.True(authorization.Authorized)
	suite.Equal("", authorization.WWWAuthenticateHeader)
	suite.Nil(err)

	// Anonymous Push, no username/password (POST/PushAction)
	req, _ = http.NewRequest(http.MethodPost, "/api/charts", nil)
	authorization, err = suite.BasicAuthAnonymousPushAuthorizer.AuthorizeRequest(req, PushAction, "")
	suite.True(authorization.Authorized)
	suite.Equal("", authorization.WWWAuthenticateHeader)
	suite.Nil(err)
}

func TestAuthorizationTestSuite(t *testing.T) {
	suite.Run(t, new(AuthorizationTestSuite))
}
