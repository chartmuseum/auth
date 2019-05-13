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
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/suite"
)

type TokenTestSuite struct {
	suite.Suite
}

var (
	testPublicKey  = "./testdata/server.pem"
	testPrivateKey = "./testdata/server.key"

	// must generate from testPrivateKey
	testKIDHeader = "AXMA:7DSP:EET7:B6VI:57ZI:53AR:MZFI:7CPX:O77L:SVJG:6GXN:IOYS"

	testNamespace = "myorg/myrepo"

	testAccess = []AccessEntry{
		{
			Name:    testNamespace,
			Type:    AccessEntryType,
			Actions: []string{PullAction},
		},
	}
)

func (suite *TokenTestSuite) SetupSuite() {
	return
}

func (suite *TokenTestSuite) TearDownSuite() {
	return
}

func (suite *TokenTestSuite) TestGenerateToken() {
	generator, err := NewTokenGenerator(&TokenGeneratorOptions{
		PrivateKeyPath: testPrivateKey,
	})
	suite.Nil(err)

	signedString, err := generator.GenerateToken(testAccess, time.Minute*5)
	suite.Nil(err)

	decoder, err := NewTokenDecoder(&TokenDecoderOptions{
		PublicKeyPath: testPublicKey,
	})
	suite.Nil(err)

	token, err := decoder.DecodeToken(signedString)
	suite.Nil(err)

	suite.Equal(PullAction, token.Claims.(jwt.MapClaims)["access"].([]interface{})[0].(map[string]interface{})["actions"].([]interface{})[0])

	suite.Empty(token.Header["kid"])

	suite.Empty(token.Claims.(jwt.MapClaims)["aud"])
	suite.Empty(token.Claims.(jwt.MapClaims)["iss"])
}

func (suite *TokenTestSuite) TestGenerateTokenAddKIDHeader() {
	generator, err := NewTokenGenerator(&TokenGeneratorOptions{
		PrivateKeyPath: testPrivateKey,
		AddKIDHeader:   true,
	})
	suite.Nil(err)

	signedString, err := generator.GenerateToken(testAccess, time.Minute*5)
	suite.Nil(err)

	decoder, err := NewTokenDecoder(&TokenDecoderOptions{
		PublicKeyPath: testPublicKey,
	})
	suite.Nil(err)

	token, err := decoder.DecodeToken(signedString)
	suite.Nil(err)

	suite.Equal(PullAction, token.Claims.(jwt.MapClaims)["access"].([]interface{})[0].(map[string]interface{})["actions"].([]interface{})[0])

	suite.Equal(testKIDHeader, token.Header["kid"])

	suite.Empty(token.Claims.(jwt.MapClaims)["aud"])
	suite.Empty(token.Claims.(jwt.MapClaims)["iss"])
}

func (suite *TokenTestSuite) TestGenerateTokenWithAudienceIssuer() {
	generator, err := NewTokenGenerator(&TokenGeneratorOptions{
		PrivateKeyPath: testPrivateKey,
		Audience:       "myaud",
		Issuer:         "myiss",
	})
	suite.Nil(err)

	signedString, err := generator.GenerateToken(testAccess, time.Minute*5)
	suite.Nil(err)

	decoder, err := NewTokenDecoder(&TokenDecoderOptions{
		PublicKeyPath: testPublicKey,
	})
	suite.Nil(err)

	token, err := decoder.DecodeToken(signedString)
	suite.Nil(err)

	suite.Equal(PullAction, token.Claims.(jwt.MapClaims)["access"].([]interface{})[0].(map[string]interface{})["actions"].([]interface{})[0])

	suite.Empty(token.Header["kid"])

	suite.Equal("myaud", token.Claims.(jwt.MapClaims)["aud"])
	suite.Equal("myiss", token.Claims.(jwt.MapClaims)["iss"])
}

func TestTokenTestSuite(t *testing.T) {
	suite.Run(t, new(TokenTestSuite))
}
