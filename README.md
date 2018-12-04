# chartmuseum/auth

[![Codefresh build status]( https://g.codefresh.io/api/badges/pipeline/chartmuseum/chartmuseum%2Fauth%2Fmaster?type=cf-1)]( https://g.codefresh.io/public/accounts/chartmuseum/pipelines/chartmuseum/auth/master)
[![Go Report Card](https://goreportcard.com/badge/github.com/chartmuseum/auth)](https://goreportcard.com/report/github.com/chartmuseum/auth)
[![GoDoc](https://godoc.org/github.com/chartmuseum/auth?status.svg)](https://godoc.org/github.com/chartmuseum/auth)

Go library for generating [ChartMuseum](https://github.com/helm/chartmuseum) JWT Tokens, authorizing HTTP requests, etc.

## How to Use

### Generating a JWT token (example)

Clone this repo and run `make getjwt` to run this example

```go
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
			Actions: []string{cmAuth.PushAction},
		},
	}
	token, err := cmTokenGenerator.GenerateToken(access, time.Minute*5)
	if err != nil {
		panic(err)
	}

	// Prints a JWT token which you can use to make requests to ChartMuseum
	fmt.Println(token)
}
```

This token will be formatted as a valid JSON Web Token (JWT)
and resemble the following:

```
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1NDM5MjYzODgsImFjY2VzcyI6W3sidHlwZSI6ImhlbG0tcmVwb3NpdG9yeSIsIm5hbWUiOiJvcmcxL3JlcG8xIiwiYWN0aW9ucyI6WyJwdXNoIl19XX0.lDIEwWTwT_PdIBwYAiJ1HXkpgAKkBiHYqX27i4SL_s9tkDLVoN8wUA0jKvwz322ev7Zm8Hu1oDuYft72vDeJkMDUgSC82d36NNmaWLyKau2GD8qsNFiRV5uwrwvJ4j2B-3NE4xJ-FjTcNYvM4Wn2gSwh1QmPYMekgbpIDcdPPa9lnR5K3KPAThLdhti3dQZ75A_3qRAp9Pw8mByeDUuJA-pEbSKPt4tTyecbJe4XON1Xb_sSI_-hoQkbBS_WhRMvKeSq9AONLYEsL4KG2BEALPDl1FEc1-KJVifLy8oWW-vPBZ3TiPaIA7ysot_gE9CgnF7mWoF8af_aD00W_OgBeg
```

You can decode this token on [https://jwt.io](http://jwt.io/#id_token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1NDM5MjYzODgsImFjY2VzcyI6W3sidHlwZSI6ImhlbG0tcmVwb3NpdG9yeSIsIm5hbWUiOiJvcmcxL3JlcG8xIiwiYWN0aW9ucyI6WyJwdXNoIl19XX0.lDIEwWTwT_PdIBwYAiJ1HXkpgAKkBiHYqX27i4SL_s9tkDLVoN8wUA0jKvwz322ev7Zm8Hu1oDuYft72vDeJkMDUgSC82d36NNmaWLyKau2GD8qsNFiRV5uwrwvJ4j2B-3NE4xJ-FjTcNYvM4Wn2gSwh1QmPYMekgbpIDcdPPa9lnR5K3KPAThLdhti3dQZ75A_3qRAp9Pw8mByeDUuJA-pEbSKPt4tTyecbJe4XON1Xb_sSI_-hoQkbBS_WhRMvKeSq9AONLYEsL4KG2BEALPDl1FEc1-KJVifLy8oWW-vPBZ3TiPaIA7ysot_gE9CgnF7mWoF8af_aD00W_OgBeg)
or with something like [jwt-cli](https://github.com/mike-engel/jwt-cli).

The decoded payload of this token will look like the following:
```json
{
  "exp": 1543925949,
  "access": [
    {
      "type": "helm-repository",
      "name": "org1/repo1",
      "actions": [
        "push"
      ]
    }
  ]
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



