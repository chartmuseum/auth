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

package main

import (
	"encoding/json"
	"fmt"
	"os"

	cmAuth "github.com/chartmuseum/auth"

	"github.com/golang-jwt/jwt"
)

func main() {
	signedString := os.Args[1]

	// This should be the public key associated with the private key used
	// to sign the token
	cmTokenDecoder, err := cmAuth.NewTokenDecoder(&cmAuth.TokenDecoderOptions{
		PublicKeyPath: "./testdata/server.pem",
	})
	if err != nil {
		panic(err)
	}

	token, err := cmTokenDecoder.DecodeToken(signedString)
	if err != nil {
		panic(err)
	}

	// Inspect the token claims as JSON
	c := token.Claims.(jwt.MapClaims)
	byteData, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		panic(err)
	}
	fmt.Println(string(byteData))
}
