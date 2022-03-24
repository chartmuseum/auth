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
	"time"

	"github.com/golang-jwt/jwt/v4"
)

const (
	AccessEntryType          = "artifact-repository"
	AllowedActionsSearchPath = "access[?name=='$NAMESPACE' && type=='$ACCESS_ENTRY_TYPE'].actions[]"
)

type (
	Claims struct {
		*jwt.StandardClaims
		Access   []AccessEntry `json:"access"`
		Audience string        `json:"aud,omitempty"`
		Issuer   string        `json:"iss,omitempty"`
	}

	AccessEntry struct {
		Type    string   `json:"type"`
		Name    string   `json:"name"`
		Actions []string `json:"actions"`
	}

	TokenGenerator struct {
		PrivateKey *rsa.PrivateKey
		Audience   string
		Issuer     string
		KID        string
	}

	TokenGeneratorOptions struct {
		PrivateKey     []byte
		PrivateKeyPath string
		Audience       string
		Issuer         string
		AddKIDHeader   bool
	}

	TokenDecoder struct {
		PublicKey *rsa.PublicKey
	}

	TokenDecoderOptions struct {
		PublicKey     []byte
		PublicKeyPath string
	}
)

func NewTokenGenerator(opts *TokenGeneratorOptions) (*TokenGenerator, error) {
	privateKey, err := generatePrivateKey(opts.PrivateKeyPath, opts.PrivateKey)
	if err != nil {
		return nil, err
	}

	tokenGenerator := TokenGenerator{
		PrivateKey: privateKey,
		Audience:   opts.Audience,
		Issuer:     opts.Issuer,
	}

	if opts.AddKIDHeader {
		kid, err := generateKIDFromPublicKey(&privateKey.PublicKey)
		if err != nil {
			return nil, err
		}
		tokenGenerator.KID = kid
	}

	return &tokenGenerator, nil
}

// currently this only works with RSA key signing
// TODO: how best to handle many different signing algorithms?
func (tokenGenerator *TokenGenerator) GenerateToken(access []AccessEntry, expiration time.Duration) (string, error) {
	token := jwt.New(jwt.SigningMethodRS256)

	if tokenGenerator.KID != "" {
		token.Header["kid"] = tokenGenerator.KID
	}

	standardClaims := jwt.StandardClaims{}

	now := time.Now()
	standardClaims.IssuedAt = now.Unix()

	if expiration > 0 {
		standardClaims.ExpiresAt = time.Now().Add(expiration).Unix()
	}

	token.Claims = &Claims{
		StandardClaims: &standardClaims,
		Access:         access,
		Audience:       tokenGenerator.Audience,
		Issuer:         tokenGenerator.Issuer,
	}
	return token.SignedString(tokenGenerator.PrivateKey)
}

func NewTokenDecoder(opts *TokenDecoderOptions) (*TokenDecoder, error) {
	publicKey, err := generatePublicKey(opts.PublicKeyPath, opts.PublicKey)
	if err != nil {
		return nil, err
	}

	tokenDecoder := TokenDecoder{
		PublicKey: publicKey,
	}
	return &tokenDecoder, nil
}

func (tokenDecoder *TokenDecoder) DecodeToken(signedString string) (*jwt.Token, error) {
	return jwt.Parse(signedString, func(token *jwt.Token) (interface{}, error) {
		return tokenDecoder.PublicKey, nil
	})
}
