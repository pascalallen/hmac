package hmac

import (
	"fmt"
)

type RequestService struct {
	public  string
	private string
}

func NewRequestService(public string, private string) (*RequestService, error) {
	if len(public) == 0 {
		return nil, fmt.Errorf("public key required")
	}

	if len(private) == 0 {
		return nil, fmt.Errorf("private key required")
	}

	// TODO

	r := RequestService{public, private}

	return &r, nil
}
