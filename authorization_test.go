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

	BasicAuthAuthorizer              *Authorizer
	BasicAuthAnonymousPullAuthorizer *Authorizer
	BasicAuthAnonymousPushAuthorizer *Authorizer

	BearerAuthAuthorizer              *Authorizer
	BearerAuthAnonymousPullAuthorizer *Authorizer
	BearerAuthAnonymousPushAuthorizer *Authorizer

	UnknownTypeAuthorizer *Authorizer
}

var (
	testPrivateKey = "./testdata/server.key"
	testPublicKey = "./testdata/server.pem"
)

func (suite *AuthorizationTestSuite) SetupSuite() {
	var err error

	suite.BasicAuthAuthorizer, err = NewAuthorizer(&AuthorizerOptions{
		Realm:            "cm-test-realm",
		Username:         "cm-test-user",
		Password:         "cm-test-pass",
	})
	suite.Nil(err)

	suite.BasicAuthAnonymousPullAuthorizer, err = NewAuthorizer(&AuthorizerOptions{
		Realm:            "cm-test-realm",
		Username:         "cm-test-user",
		Password:         "cm-test-pass",
		AnonymousActions: []string{PullAction},
	})
	suite.Nil(err)

	suite.BasicAuthAnonymousPushAuthorizer, err = NewAuthorizer(&AuthorizerOptions{
		Realm:            "cm-test-realm",
		Username:         "cm-test-user",
		Password:         "cm-test-pass",
		AnonymousActions: []string{PullAction, PushAction},
	})
	suite.Nil(err)

	suite.BearerAuthAuthorizer, err = NewAuthorizer(&AuthorizerOptions{
		Realm: "cm-test-realm",
		PublicCertPath: testPublicKey,
	})
	suite.Nil(err)

	suite.BearerAuthAnonymousPullAuthorizer, err = NewAuthorizer(&AuthorizerOptions{
		Realm: "cm-test-realm",
		PublicCertPath: testPublicKey,
		AnonymousActions: []string{PullAction},
	})
	suite.Nil(err)

	suite.BearerAuthAnonymousPushAuthorizer, err = NewAuthorizer(&AuthorizerOptions{
		Realm: "cm-test-realm",
		PublicCertPath: testPublicKey,
		AnonymousActions: []string{PullAction, PushAction},
	})
	suite.Nil(err)

	suite.UnknownTypeAuthorizer = &Authorizer{Type: AuthorizerType("unknown")}
}

func (suite *AuthorizationTestSuite) TearDownSuite() {
	return
}

func (suite *AuthorizationTestSuite) TestNewAuthorizer() {
	authorizer, err := NewAuthorizer(&AuthorizerOptions{
		Realm: "cm-test-realm",
	})
	suite.Nil(authorizer)
	suite.NotNil(err)
}

func (suite *AuthorizationTestSuite) TestAuthorizeRequest() {
	var permission *Permission
	var err error

	badAuthorizationHeader := generateBasicAuthHeader("cm-test-baduser", "cm-test-badpass")
	goodAuthorizationHeader := generateBasicAuthHeader("cm-test-user", "cm-test-pass")

	expectedWWWAuthHeader := "Basic realm=\"cm-test-realm\""

	// Unknown authorizer type returns err
	permission, err = suite.UnknownTypeAuthorizer.Authorize(goodAuthorizationHeader, PullAction, "")
	suite.Nil(permission)
	suite.NotNil(err)

	// No username/password
	permission, err = suite.BasicAuthAuthorizer.Authorize("", PullAction, "")
	suite.False(permission.Allowed)
	suite.Equal(expectedWWWAuthHeader, permission.WWWAuthenticateHeader)
	suite.Nil(err)

	// Bad username/password
	permission, err = suite.BasicAuthAuthorizer.Authorize(badAuthorizationHeader, PullAction, "")
	suite.False(permission.Allowed)
	suite.Equal(expectedWWWAuthHeader, permission.WWWAuthenticateHeader)
	suite.Nil(err)

	// Correct username/password
	permission, err = suite.BasicAuthAuthorizer.Authorize(goodAuthorizationHeader, PullAction, "")
	suite.True(permission.Allowed)
	suite.Equal("", permission.WWWAuthenticateHeader)
	suite.Nil(err)

	// Anonymous Pull, no username/password (GET/PullAction)
	permission, err = suite.BasicAuthAnonymousPullAuthorizer.Authorize("", PullAction, "")
	suite.True(permission.Allowed)
	suite.Equal("", permission.WWWAuthenticateHeader)
	suite.Nil(err)

	// Anonymous Pull, no username/password (POST/PushAction)
	permission, err = suite.BasicAuthAnonymousPullAuthorizer.Authorize("", PushAction, "")
	suite.False(permission.Allowed)
	suite.Equal(expectedWWWAuthHeader, permission.WWWAuthenticateHeader)
	suite.Nil(err)

	// Anonymous Push, no username/password (GET/PullAction)
	permission, err = suite.BasicAuthAnonymousPushAuthorizer.Authorize("", PullAction, "")
	suite.True(permission.Allowed)
	suite.Equal("", permission.WWWAuthenticateHeader)
	suite.Nil(err)

	// Anonymous Push, no username/password (POST/PushAction)
	permission, err = suite.BasicAuthAnonymousPushAuthorizer.Authorize("", PushAction, "")
	suite.True(permission.Allowed)
	suite.Equal("", permission.WWWAuthenticateHeader)
	suite.Nil(err)
}

func TestAuthorizationTestSuite(t *testing.T) {
	suite.Run(t, new(AuthorizationTestSuite))
}
