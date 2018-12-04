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
	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/suite"
	"testing"
)

type TokenTestSuite struct {
	suite.Suite
}

var (
	testPublicKey  = "./testdata/server.pem"
	testPrivateKey = "./testdata/server.key"
)

func (suite *TokenTestSuite) SetupSuite() {
	return
}

func (suite *TokenTestSuite) TearDownSuite() {
	return
}

func (suite *TokenTestSuite) TestGenerateToken() {
	generator, err := NewTokenGenerator(&TokenGeneratorOptions{
		PrivateCertPath: testPrivateKey,
	})
	suite.Nil(err)

	namespace := "myorg/myrepo"
	access := []AccessEntry{
		{
			Name:    namespace,
			Type:    DefaultAccessEntryType,
			Actions: []string{PullAction},
		},
	}

	signedString, err := generator.GenerateToken(access, DefaultExpiration)
	suite.Nil(err)

	decoder, err := NewTokenDecoder(&TokenDecoderOptions{
		PublicCertPath: testPublicKey,
	})
	suite.Nil(err)

	token, err := decoder.DecodeToken(signedString)
	suite.Nil(err)

	suite.Equal(PullAction, token.Claims.(jwt.MapClaims)["access"].([]interface{})[0].(map[string]interface{})["actions"].([]interface{})[0])
}

func TestTokenTestSuite(t *testing.T) {
	suite.Run(t, new(TokenTestSuite))
}
