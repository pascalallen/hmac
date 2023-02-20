# hmac

[![Go Reference](https://pkg.go.dev/badge/github.com/pascalallen/hmac.svg)](https://pkg.go.dev/github.com/pascalallen/hmac)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/pascalallen/hmac)
[![Go Report Card](https://goreportcard.com/badge/github.com/pascalallen/hmac)](https://goreportcard.com/report/github.com/pascalallen/hmac)
![GitHub Workflow Status (with branch)](https://img.shields.io/github/actions/workflow/status/pascalallen/hmac/go.yml?branch=main)
![GitHub](https://img.shields.io/github/license/pascalallen/hmac)
![GitHub code size in bytes](https://img.shields.io/github/languages/code-size/pascalallen/hmac)

hmac is a Go module that offers services for HTTP HMAC authentication.

## Installation

Use the Go CLI tool [go](https://go.dev/dl/) to install hmac.

```bash
go get github.com/pascalallen/hmac
```

## Usage

```go
...

import "github.com/pascalallen/hmac"

...

publicKey := hmac.GenerateSecureRandom(16)
privateKey := hmac.GenerateSecureRandom(16)
var timeTolerance int64 = 300

request, _ := http.NewRequest(
    http.MethodPost,
    "http://localhost:8080?abc=xyz",
    bytes.NewReader([]byte(`{"foo": "bar"}`)),
)

// create request service and sign request
requestService, _ := hmac.NewRequestService(publicKey, privateKey)
signedRequest := requestService.SignRequest(request)

// create authenticator and validate signed request
authenticator, _ := hmac.NewAuthenticator(publicKey, privateKey, timeTolerance)
isValid := authenticator.Validate(*signedRequest)

...
```

## Testing

Run tests and create coverage profile:

```bash
go test -covermode=count -coverprofile=coverage.out
```

View test coverage profile:

```bash
go tool cover -html=coverage.out
```

## Contributing

Pull requests are welcome. For major changes, please open an issue first
to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License

[MIT](LICENSE)