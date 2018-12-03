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
	var authorization *Authorization
	var err error

	badAuthorizationHeader := generateBasicAuthHeader("cm-test-baduser", "cm-test-badpass")
	goodAuthorizationHeader := generateBasicAuthHeader("cm-test-user", "cm-test-pass")

	expectedWWWAuthHeader := "Basic realm=\"cm-test-realm\""

	// No username/password
	authorization, err = suite.BasicAuthAuthorizer.Authorize("", PullAction, "")
	suite.False(authorization.Authorized)
	suite.Equal(expectedWWWAuthHeader, authorization.WWWAuthenticateHeader)
	suite.Nil(err)

	// Bad username/password
	authorization, err = suite.BasicAuthAuthorizer.Authorize(badAuthorizationHeader, PullAction, "")
	suite.False(authorization.Authorized)
	suite.Equal(expectedWWWAuthHeader, authorization.WWWAuthenticateHeader)
	suite.Nil(err)

	// Correct username/password
	authorization, err = suite.BasicAuthAuthorizer.Authorize(goodAuthorizationHeader, PullAction, "")
	suite.True(authorization.Authorized)
	suite.Equal("", authorization.WWWAuthenticateHeader)
	suite.Nil(err)

	// Anonymous Pull, no username/password (GET/PullAction)
	authorization, err = suite.BasicAuthAnonymousPullAuthorizer.Authorize("", PullAction, "")
	suite.True(authorization.Authorized)
	suite.Equal("", authorization.WWWAuthenticateHeader)
	suite.Nil(err)

	// Anonymous Pull, no username/password (POST/PushAction)
	authorization, err = suite.BasicAuthAnonymousPullAuthorizer.Authorize("", PushAction, "")
	suite.False(authorization.Authorized)
	suite.Equal(expectedWWWAuthHeader, authorization.WWWAuthenticateHeader)
	suite.Nil(err)

	// Anonymous Push, no username/password (GET/PullAction)
	authorization, err = suite.BasicAuthAnonymousPushAuthorizer.Authorize("", PullAction, "")
	suite.True(authorization.Authorized)
	suite.Equal("", authorization.WWWAuthenticateHeader)
	suite.Nil(err)

	// Anonymous Push, no username/password (POST/PushAction)
	authorization, err = suite.BasicAuthAnonymousPushAuthorizer.Authorize("", PushAction, "")
	suite.True(authorization.Authorized)
	suite.Equal("", authorization.WWWAuthenticateHeader)
	suite.Nil(err)
}

func TestAuthorizationTestSuite(t *testing.T) {
	suite.Run(t, new(AuthorizationTestSuite))
}
