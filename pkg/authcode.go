package pkg

import (
	"crypto"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/pkg/errors"
)

type RequestObjectProducer struct {
	EntityID string
	lifetime int64
	key      crypto.Signer
	alg      jwa.SignatureAlgorithm
}

// NewRequestObjectProducer creates a new RequestObjectProducer with the passed properties
func NewRequestObjectProducer(
	entityID string, privateSigningKey crypto.Signer, signingAlg jwa.SignatureAlgorithm, lifetime int64,
) *RequestObjectProducer {
	return &RequestObjectProducer{
		EntityID: entityID,
		lifetime: lifetime,
		key:      privateSigningKey,
		alg:      signingAlg,
	}
}

func (rop RequestObjectProducer) RequestObject(requestValues map[string]any) ([]byte, error) {
	if _, audFound := requestValues["aud"]; !audFound {
		return nil, errors.New("request must contain 'aud' claim with OPs issuer identifier url")
	}
	requestValues["iss"] = rop.EntityID
	requestValues["client_id"] = rop.EntityID
	delete(requestValues, "sub")
	delete(requestValues, "client_secret")
	if _, jtiFound := requestValues["jti"]; !jtiFound {
		jti, err := uuid.NewRandom()
		if err != nil {
			return nil, errors.Wrap(err, "could not create jti")
		}
		requestValues["jti"] = jti.String()
	}
	now := time.Now().Unix()
	requestValues["iat"] = now
	requestValues["exp"] = now + rop.lifetime

	j, err := json.Marshal(requestValues)
	if err != nil {
		return nil, errors.Wrap(err, "could not marshal request object into JWT")
	}

	return jws.Sign(j, rop.alg, rop.key)
}
