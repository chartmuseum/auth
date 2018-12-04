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
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

type AuthorizationTestSuite struct {
	suite.Suite

	TokenGenerator *TokenGenerator

	BasicAuthAuthorizer              *Authorizer
	BasicAuthAnonymousPullAuthorizer *Authorizer
	BasicAuthAnonymousPushAuthorizer *Authorizer

	BearerAuthAuthorizer              *Authorizer
	BearerAuthAnonymousPullAuthorizer *Authorizer
	BearerAuthAnonymousPushAuthorizer *Authorizer

	UnknownTypeAuthorizer *Authorizer

	BasicBadAuthorizationHeader          string
	BasicGoodAuthorizationHeader         string
	BasicExpectedWWWAuthHeader           string
	BearerPullScopeExpectedWWWAuthHeader string
	BearerPushScopeExpectedWWWAuthHeader string
}

func (suite *AuthorizationTestSuite) SetupSuite() {
	var err error

	generator, err := NewTokenGenerator(&TokenGeneratorOptions{PrivateCertPath: testPrivateKey})
	suite.Nil(err)

	suite.TokenGenerator = generator

	suite.BasicAuthAuthorizer, err = NewAuthorizer(&AuthorizerOptions{
		Realm:    "cm-test-realm",
		Username: "cm-test-user",
		Password: "cm-test-pass",
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
		Realm:          "cm-test-realm",
		PublicCertPath: testPublicKey,
	})
	suite.Nil(err)

	suite.BearerAuthAnonymousPullAuthorizer, err = NewAuthorizer(&AuthorizerOptions{
		Realm:            "cm-test-realm",
		PublicCertPath:   testPublicKey,
		AnonymousActions: []string{PullAction},
	})
	suite.Nil(err)

	suite.BearerAuthAnonymousPushAuthorizer, err = NewAuthorizer(&AuthorizerOptions{
		Realm:            "cm-test-realm",
		PublicCertPath:   testPublicKey,
		AnonymousActions: []string{PullAction, PushAction},
	})
	suite.Nil(err)

	suite.UnknownTypeAuthorizer = &Authorizer{Type: AuthorizerType("unknown")}

	suite.BasicBadAuthorizationHeader = generateBasicAuthHeader("cm-test-baduser", "cm-test-badpass")
	suite.BasicGoodAuthorizationHeader = generateBasicAuthHeader("cm-test-user", "cm-test-pass")
	suite.BasicExpectedWWWAuthHeader = "Basic realm=\"cm-test-realm\""
	suite.BearerPullScopeExpectedWWWAuthHeader = "Bearer realm=\"cm-test-realm\""
	suite.BearerPushScopeExpectedWWWAuthHeader = "Bearer realm=\"cm-test-realm\""
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

func (suite *AuthorizationTestSuite) TestAuthorizeBasicRequest() {
	var permission *Permission
	var err error

	expectedWWWAuthHeader := "Basic realm=\"cm-test-realm\""

	// Unknown authorizer type returns err
	permission, err = suite.UnknownTypeAuthorizer.Authorize(suite.BasicGoodAuthorizationHeader, PullAction, "")
	suite.Nil(permission)
	suite.NotNil(err)

	// No username/password
	permission, err = suite.BasicAuthAuthorizer.Authorize("", PullAction, "")
	suite.False(permission.Allowed)
	suite.Equal(expectedWWWAuthHeader, permission.WWWAuthenticateHeader)
	suite.Nil(err)

	// Bad username/password
	permission, err = suite.BasicAuthAuthorizer.Authorize(suite.BasicBadAuthorizationHeader, PullAction, "")
	suite.False(permission.Allowed)
	suite.Equal(expectedWWWAuthHeader, permission.WWWAuthenticateHeader)
	suite.Nil(err)

	// Correct username/password
	permission, err = suite.BasicAuthAuthorizer.Authorize(suite.BasicGoodAuthorizationHeader, PullAction, "")
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

	// No username/password
	permission, err = suite.BasicAuthAuthorizer.Authorize("", PullAction, "")
	suite.False(permission.Allowed)
	suite.Equal(expectedWWWAuthHeader, permission.WWWAuthenticateHeader)
	suite.Nil(err)
}

func (suite *AuthorizationTestSuite) TestAuthorizeBearerRequest() {
	var permission *Permission
	var err error

	// No token
	permission, err = suite.BearerAuthAuthorizer.Authorize("", PullAction, "")
	suite.False(permission.Allowed)
	suite.Equal(suite.BearerPullScopeExpectedWWWAuthHeader, permission.WWWAuthenticateHeader)
	suite.Nil(err)

	// Valid token
	access := []AccessEntry{
		{
			Name:    "",
			Type:    DefaultAccessEntryType,
			Actions: []string{PullAction},
		},
	}
	signedString, err := suite.TokenGenerator.GenerateToken(access, 0)
	suite.Nil(err)
	authHeader := fmt.Sprintf("Bearer %s", signedString)
	permission, err = suite.BearerAuthAuthorizer.Authorize(authHeader, PullAction, "")
	suite.True(permission.Allowed)
	suite.Equal("", permission.WWWAuthenticateHeader)
	suite.Nil(err)

	// Namespace checks
	access = []AccessEntry{
		{
			Name:    "",
			Type:    DefaultAccessEntryType,
			Actions: []string{PullAction},
		},
		{
			Name:    "org1/repo1",
			Type:    DefaultAccessEntryType,
			Actions: []string{PullAction},
		},
		{
			Name:    "org1/repo2",
			Type:    DefaultAccessEntryType,
			Actions: []string{PullAction, PushAction},
		},
	}
	signedString, err = suite.TokenGenerator.GenerateToken(access, 0)
	suite.Nil(err)
	authHeader = fmt.Sprintf("Bearer %s", signedString)

	permission, err = suite.BearerAuthAuthorizer.Authorize(authHeader, PullAction, "")
	suite.True(permission.Allowed)
	suite.Equal("", permission.WWWAuthenticateHeader)
	suite.Nil(err)

	permission, err = suite.BearerAuthAuthorizer.Authorize(authHeader, PullAction, "org1/repo1")
	suite.True(permission.Allowed)
	suite.Equal("", permission.WWWAuthenticateHeader)
	suite.Nil(err)

	permission, err = suite.BearerAuthAuthorizer.Authorize(authHeader, PullAction, "org1/repo2")
	suite.True(permission.Allowed)
	suite.Equal("", permission.WWWAuthenticateHeader)
	suite.Nil(err)

	permission, err = suite.BearerAuthAuthorizer.Authorize(authHeader, PushAction, "")
	suite.False(permission.Allowed)
	suite.Equal(suite.BearerPullScopeExpectedWWWAuthHeader, permission.WWWAuthenticateHeader)
	suite.Nil(err)

	permission, err = suite.BearerAuthAuthorizer.Authorize(authHeader, PushAction, "org1/repo1")
	suite.False(permission.Allowed)
	suite.Equal(suite.BearerPullScopeExpectedWWWAuthHeader, permission.WWWAuthenticateHeader)
	suite.Nil(err)

	permission, err = suite.BearerAuthAuthorizer.Authorize(authHeader, PushAction, "org1/repo2")
	suite.True(permission.Allowed)
	suite.Equal("", permission.WWWAuthenticateHeader)
	suite.Nil(err)

	// Expired Token
	access = []AccessEntry{
		{
			Name:    "",
			Type:    DefaultAccessEntryType,
			Actions: []string{PullAction},
		},
	}
	signedString, err = suite.TokenGenerator.GenerateToken(access, time.Second*1)
	suite.Nil(err)
	fmt.Println("Sleeping for 2 seconds to test token expiration...")
	time.Sleep(time.Second * 2)
	authHeader = fmt.Sprintf("Bearer %s", signedString)
	permission, err = suite.BearerAuthAuthorizer.Authorize(authHeader, PullAction, "")
	suite.False(permission.Allowed)
	suite.Equal(suite.BearerPullScopeExpectedWWWAuthHeader, permission.WWWAuthenticateHeader)
	suite.Nil(err)

	// Token entry type is not recognized
	access = []AccessEntry{
		{
			Name:    "",
			Type:    "fake-type",
			Actions: []string{PullAction},
		},
	}
	signedString, err = suite.TokenGenerator.GenerateToken(access, 0)
	suite.Nil(err)
	authHeader = fmt.Sprintf("Bearer %s", signedString)
	permission, err = suite.BearerAuthAuthorizer.Authorize(authHeader, PullAction, "")
	suite.False(permission.Allowed)
	suite.Equal(suite.BearerPullScopeExpectedWWWAuthHeader, permission.WWWAuthenticateHeader)
	suite.Nil(err)

	// Token entry does not have action requested
	access = []AccessEntry{
		{
			Name:    "",
			Type:    DefaultAccessEntryType,
			Actions: []string{},
		},
	}
	signedString, err = suite.TokenGenerator.GenerateToken(access, 0)
	suite.Nil(err)
	authHeader = fmt.Sprintf("Bearer %s", signedString)
	permission, err = suite.BearerAuthAuthorizer.Authorize(authHeader, PullAction, "")
	suite.False(permission.Allowed)
	suite.Equal(suite.BearerPullScopeExpectedWWWAuthHeader, permission.WWWAuthenticateHeader)
	suite.Nil(err)
}

func TestAuthorizationTestSuite(t *testing.T) {
	suite.Run(t, new(AuthorizationTestSuite))
}
