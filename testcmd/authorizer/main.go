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
	"fmt"
	"os"

	cmAuth "github.com/chartmuseum/auth"
)

func main() {

	// We are grabbing this from command line, but this should be obtained
	// by inspecting the "Authorization" header of an incoming HTTP request
	signedString := os.Args[1]
	authHeader := fmt.Sprintf("Bearer %s", signedString)

	cmAuthorizer, err := cmAuth.NewAuthorizer(&cmAuth.AuthorizerOptions{
		Realm:         "cm-test-realm",
		PublicKeyPath: "./testdata/server.pem",
	})
	if err != nil {
		panic(err)
	}

	// Example:
	// Check if the auth header provided allows access to push to org1/repo1
	permissions, err := cmAuthorizer.Authorize(authHeader, cmAuth.PushAction, "org1/repo1")
	if err != nil {
		panic(err)
	}

	if permissions.Allowed {
		fmt.Println("ACCESS GRANTED")
	} else {

		// If access is not allowed, the WWWAuthenticateHeader will be populated
		// which should be sent back to the client in the "WWW-Authenticate" header
		fmt.Println("ACCESS DENIED")
		fmt.Println(fmt.Sprintf("WWW-Authenticate: %s", permissions.WWWAuthenticateHeader))
	}
}
