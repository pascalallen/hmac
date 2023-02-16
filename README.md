# hmac

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
timeTolerance := 300

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