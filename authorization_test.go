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
	"strings"
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

	CustomAccessEntryTypeAuthorizer *Authorizer

	BasicBadAuthorizationHeader          string
	BasicGoodAuthorizationHeader         string
	BasicExpectedWWWAuthHeader           string
	BearerPullScopeExpectedWWWAuthHeader string
	BearerPushScopeExpectedWWWAuthHeader string
}

func (suite *AuthorizationTestSuite) SetupSuite() {
	var err error

	generator, err := NewTokenGenerator(&TokenGeneratorOptions{PrivateKeyPath: testPrivateKey})
	suite.Nil(err)

	suite.TokenGenerator = generator

	suite.BasicAuthAuthorizer, err = NewAuthorizer(&AuthorizerOptions{
		Realm:    "https://my.site.io/oauth2/token",
		Username: "cm-test-user",
		Password: "cm-test-pass",
	})
	suite.Nil(err)

	suite.BasicAuthAnonymousPullAuthorizer, err = NewAuthorizer(&AuthorizerOptions{
		Realm:            "https://my.site.io/oauth2/token",
		Username:         "cm-test-user",
		Password:         "cm-test-pass",
		AnonymousActions: []string{PullAction},
	})
	suite.Nil(err)

	suite.BasicAuthAnonymousPushAuthorizer, err = NewAuthorizer(&AuthorizerOptions{
		Realm:            "https://my.site.io/oauth2/token",
		Username:         "cm-test-user",
		Password:         "cm-test-pass",
		AnonymousActions: []string{PullAction, PushAction},
	})
	suite.Nil(err)

	suite.BearerAuthAuthorizer, err = NewAuthorizer(&AuthorizerOptions{
		Realm:         "https://my.site.io/oauth2/token",
		Service:       "my.site.io",
		PublicKeyPath: testPublicKey,
	})
	suite.Nil(err)

	suite.BearerAuthAnonymousPullAuthorizer, err = NewAuthorizer(&AuthorizerOptions{
		Realm:            "https://my.site.io/oauth2/token",
		Service:          "my.site.io",
		PublicKeyPath:    testPublicKey,
		AnonymousActions: []string{PullAction},
	})
	suite.Nil(err)

	suite.BearerAuthAnonymousPushAuthorizer, err = NewAuthorizer(&AuthorizerOptions{
		Realm:            "https://my.site.io/oauth2/token",
		Service:          "my.site.io",
		PublicKeyPath:    testPublicKey,
		AnonymousActions: []string{PullAction, PushAction},
	})
	suite.Nil(err)

	suite.UnknownTypeAuthorizer = &Authorizer{Type: AuthorizerType("unknown")}

	suite.CustomAccessEntryTypeAuthorizer, err = NewAuthorizer(&AuthorizerOptions{
		Realm:           "https://my.site.io/oauth2/token",
		Service:         "my.site.io",
		PublicKeyPath:   testPublicKey,
		AccessEntryType: "blah-blah-blah",
	})
	suite.Nil(err)

	suite.BasicBadAuthorizationHeader = generateBasicAuthHeader("cm-test-baduser", "cm-test-badpass")
	suite.BasicGoodAuthorizationHeader = generateBasicAuthHeader("cm-test-user", "cm-test-pass")
	suite.BasicExpectedWWWAuthHeader = "Basic realm=\"https://my.site.io/oauth2/token\""
	suite.BearerPullScopeExpectedWWWAuthHeader =
		"Bearer realm=\"https://my.site.io/oauth2/token\",service=\"my.site.io\",scope=\"artifact-repository:repo:pull\""
	suite.BearerPushScopeExpectedWWWAuthHeader =
		"Bearer realm=\"https://my.site.io/oauth2/token\",service=\"my.site.io\",scope=\"artifact-repository:repo:push\""
}

func (suite *AuthorizationTestSuite) TearDownSuite() {
	return
}

func (suite *AuthorizationTestSuite) TestNewAuthorizer() {
	authorizer, err := NewAuthorizer(&AuthorizerOptions{
		Realm: "https://my.site.io/oauth2/token",
	})
	suite.Nil(authorizer)
	suite.NotNil(err)
}

func (suite *AuthorizationTestSuite) TestAuthorizeBasicRequest() {
	var permission *Permission
	var err error

	expectedWWWAuthHeader := "Basic realm=\"https://my.site.io/oauth2/token\""

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
			Name:    DefaultNamespace,
			Type:    AccessEntryType,
			Actions: []string{PullAction},
		},
	}
	signedString, err := suite.TokenGenerator.GenerateToken(access, 0)
	suite.Nil(err)
	authHeader := fmt.Sprintf("Bearer %s", signedString)
	permission, err = suite.BearerAuthAuthorizer.Authorize(authHeader, PullAction, DefaultNamespace)
	suite.True(permission.Allowed)
	suite.Equal("", permission.WWWAuthenticateHeader)
	suite.Nil(err)

	// Namespace checks
	access = []AccessEntry{
		{
			Name:    DefaultNamespace,
			Type:    AccessEntryType,
			Actions: []string{PullAction},
		},
		{
			Name:    "org1/repo1",
			Type:    AccessEntryType,
			Actions: []string{PullAction},
		},
		{
			Name:    "org1/repo2",
			Type:    AccessEntryType,
			Actions: []string{PullAction, PushAction},
		},
	}
	signedString, err = suite.TokenGenerator.GenerateToken(access, 0)
	suite.Nil(err)
	authHeader = fmt.Sprintf("Bearer %s", signedString)

	permission, err = suite.BearerAuthAuthorizer.Authorize(authHeader, PullAction, DefaultNamespace)
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

	permission, err = suite.BearerAuthAuthorizer.Authorize(authHeader, PushAction, DefaultNamespace)
	suite.False(permission.Allowed)
	suite.Equal(suite.BearerPushScopeExpectedWWWAuthHeader, permission.WWWAuthenticateHeader)
	suite.Nil(err)

	permission, err = suite.BearerAuthAuthorizer.Authorize(authHeader, PushAction, "org1/repo1")
	suite.False(permission.Allowed)
	expectedWWWAuthHeaderRepo1 := strings.Replace(suite.BearerPushScopeExpectedWWWAuthHeader, ":repo:", ":org1/repo1:", 1)
	suite.Equal(expectedWWWAuthHeaderRepo1, permission.WWWAuthenticateHeader)
	suite.Nil(err)

	permission, err = suite.BearerAuthAuthorizer.Authorize(authHeader, PushAction, "org1/repo2")
	suite.True(permission.Allowed)
	suite.Equal("", permission.WWWAuthenticateHeader)
	suite.Nil(err)

	// Expired Token
	access = []AccessEntry{
		{
			Name:    DefaultNamespace,
			Type:    AccessEntryType,
			Actions: []string{PullAction},
		},
	}
	signedString, err = suite.TokenGenerator.GenerateToken(access, time.Second*1)
	suite.Nil(err)
	fmt.Println("Sleeping for 2 seconds to test token expiration...")
	time.Sleep(time.Second * 2)
	authHeader = fmt.Sprintf("Bearer %s", signedString)
	permission, err = suite.BearerAuthAuthorizer.Authorize(authHeader, PullAction, DefaultNamespace)
	suite.False(permission.Allowed)
	suite.Equal(suite.BearerPullScopeExpectedWWWAuthHeader, permission.WWWAuthenticateHeader)
	suite.Nil(err)

	// Token entry type is not recognized
	access = []AccessEntry{
		{
			Name:    DefaultNamespace,
			Type:    "fake-type",
			Actions: []string{PullAction},
		},
	}
	signedString, err = suite.TokenGenerator.GenerateToken(access, 0)
	suite.Nil(err)
	authHeader = fmt.Sprintf("Bearer %s", signedString)
	permission, err = suite.BearerAuthAuthorizer.Authorize(authHeader, PullAction, DefaultNamespace)
	suite.False(permission.Allowed)
	suite.Equal(suite.BearerPullScopeExpectedWWWAuthHeader, permission.WWWAuthenticateHeader)
	suite.Nil(err)

	// Token entry does not have action requested
	access = []AccessEntry{
		{
			Name:    DefaultNamespace,
			Type:    AccessEntryType,
			Actions: []string{},
		},
	}
	signedString, err = suite.TokenGenerator.GenerateToken(access, 0)
	suite.Nil(err)
	authHeader = fmt.Sprintf("Bearer %s", signedString)
	permission, err = suite.BearerAuthAuthorizer.Authorize(authHeader, PullAction, DefaultNamespace)
	suite.False(permission.Allowed)
	suite.Equal(suite.BearerPullScopeExpectedWWWAuthHeader, permission.WWWAuthenticateHeader)
	suite.Nil(err)
}

func (suite *AuthorizationTestSuite) TestCustomAccessEntryTypeAuthorizer() {
	// Using default access entry type does not provide access
	access := []AccessEntry{
		{
			Name:    DefaultNamespace,
			Type:    AccessEntryType,
			Actions: []string{PullAction},
		},
	}
	signedString, err := suite.TokenGenerator.GenerateToken(access, 0)
	suite.Nil(err)
	authHeader := fmt.Sprintf("Bearer %s", signedString)
	permission, err := suite.CustomAccessEntryTypeAuthorizer.Authorize(authHeader, PullAction, DefaultNamespace)
	suite.False(permission.Allowed)
	suite.NotEmpty(permission.WWWAuthenticateHeader)
	suite.Nil(err)

	// Using custom access entry type does indeed provide access
	access = []AccessEntry{
		{
			Name:    DefaultNamespace,
			Type:    "blah-blah-blah",
			Actions: []string{PullAction},
		},
	}
	signedString, err = suite.TokenGenerator.GenerateToken(access, 0)
	suite.Nil(err)
	authHeader = fmt.Sprintf("Bearer %s", signedString)
	permission, err = suite.CustomAccessEntryTypeAuthorizer.Authorize(authHeader, PullAction, DefaultNamespace)
	suite.True(permission.Allowed)
	suite.Empty(permission.WWWAuthenticateHeader)
	suite.Nil(err)
}

func TestAuthorizationTestSuite(t *testing.T) {
	suite.Run(t, new(AuthorizationTestSuite))
}
