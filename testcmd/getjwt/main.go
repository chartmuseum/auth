package main

import (
	"fmt"
	"time"

	cmAuth "github.com/chartmuseum/auth"
)

func main() {

	// This should be the private key associated with the public key used
	// in ChartMuseum server configuration (server.pem)
	cmTokenGenerator, err := cmAuth.NewTokenGenerator(&cmAuth.TokenGeneratorOptions{
		PrivateCertPath: "./testdata/server.key",
	})
	if err != nil {
		panic(err)
	}

	// Example:
	// Generate a token which allows the user to push to the "org1/repo1"
	// repository, and expires in 5 minutes
	access := []cmAuth.AccessEntry{
		{
			Name:    "org1/repo1",
			Type:    cmAuth.DefaultAccessEntryType,
			Actions: []string{cmAuth.PullAction},
		},
	}
	token, err := cmTokenGenerator.GenerateToken(access, time.Minute*5)
	if err != nil {
		panic(err)
	}

	// Prints a JWT token which you can use to make requests to ChartMuseum.
	// You can decode this on http://jwt.io or with something like jwt-cli
	fmt.Println(token)
}
