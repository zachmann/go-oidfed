package pkce

import (
	"crypto/sha256"
	"encoding/base64"

	"github.com/pkg/errors"
)

// PKCE is a type holding the information for a PKCE flow
type PKCE struct {
	verifier  string
	challenge string
	method    Method
}

// Method is a type for the code challenge methods
type Method string

// Defines for the possible Method
const (
	TransformationPlain = Method("plain")
	TransformationS256  = Method("S256")
)

func (m Method) String() string {
	return string(m)
}

// NewPKCE creates a new PKCE for the passed verifier and Method
func NewPKCE(verifier string, method Method) *PKCE {
	return &PKCE{
		verifier: verifier,
		method:   method,
	}
}

// NewS256PKCE creates a new PKCE for the passed verifier and the Method TransformationS256
func NewS256PKCE(verifier string) *PKCE {
	return NewPKCE(verifier, TransformationS256)
}

// Verifier returns the code_verifier
func (pkce PKCE) Verifier() string {
	return pkce.verifier
}

// Challenge returns the code_challenge according to the defined Method
func (pkce *PKCE) Challenge() (string, error) {
	var err error
	if pkce.challenge == "" {
		pkce.challenge, err = pkce.transform()
	}
	return pkce.challenge, err
}

func (pkce PKCE) transform() (string, error) {
	switch pkce.method {
	case TransformationPlain:
		return pkce.plain(), nil
	case TransformationS256:
		return pkce.s256(), nil
	default:
		return "", errors.New("unknown code_challenge_method")
	}
}

func (pkce PKCE) plain() string {
	return pkce.verifier
}

func (pkce PKCE) s256() string {
	hash := sha256.Sum256([]byte(pkce.verifier))
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(hash[:])
}
