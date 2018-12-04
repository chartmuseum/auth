# chartmuseum/auth

[![Codefresh build status]( https://g.codefresh.io/api/badges/pipeline/chartmuseum/chartmuseum%2Fauth%2Fmaster?type=cf-1)]( https://g.codefresh.io/public/accounts/chartmuseum/pipelines/chartmuseum/auth/master)
[![Go Report Card](https://goreportcard.com/badge/github.com/chartmuseum/auth)](https://goreportcard.com/report/github.com/chartmuseum/auth)
[![GoDoc](https://godoc.org/github.com/chartmuseum/auth?status.svg)](https://godoc.org/github.com/chartmuseum/auth)

Go library for generating [ChartMuseum](https://github.com/helm/chartmuseum) JWT Tokens, authorizing HTTP requests, etc.

## How to Use

### Generating a JWT token (example)

```
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
```

### Making requests to ChartMuseum

First, obtain the token with the necessary access entries (see example above).

Then use this token to make requests to ChartMuseum,
passing it in the `Authorization` header:

```
> GET /api/charts HTTP/1.1
> Host: localhost:8080
> Authorization: Bearer <token>
```



