package jwx

import (
	"bytes"
	"encoding/json"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/pkg/errors"
	"github.com/vmihailenco/msgpack/v5"
)

// JWKS is a wrapper type for jwk.Set to implement custom marshaling
type JWKS struct {
	jwk.Set
}

// NewJWKS returns a new JWKS
func NewJWKS() JWKS {
	return JWKS{jwk.NewSet()}
}

// MarshalJSON implements the json.Marshaler interface
func (jwks JWKS) MarshalJSON() ([]byte, error) {
	data, err := json.Marshal(jwks.Set)
	return data, errors.WithStack(err)
}

// UnmarshalJSON implements the json.Unmarshaler interface
func (jwks *JWKS) UnmarshalJSON(data []byte) error {
	if bytes.Equal(data, []byte("null")) {
		jwks.Set = nil
		return nil
	}
	if jwks.Set == nil {
		jwks.Set = jwk.NewSet()
	}
	if err := json.Unmarshal(data, jwks.Set); err != nil {
		return errors.WithStack(err)
	}
	if jwks.Len() == 0 {
		jwks.Set = nil
	}
	return nil
}

// MarshalMsgpack implements the msgpack.Marshaler interface
func (jwks JWKS) MarshalMsgpack() ([]byte, error) {
	data, err := json.Marshal(jwks)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	msgpackData, err := msgpack.Marshal(data)
	return msgpackData, errors.WithStack(err)
}

// UnmarshalMsgpack implements the msgpack.Unmarshaler interface
func (jwks *JWKS) UnmarshalMsgpack(data []byte) error {
	var jsonData []byte
	if err := msgpack.Unmarshal(data, &jsonData); err != nil {
		return errors.WithStack(err)
	}
	return errors.WithStack(json.Unmarshal(jsonData, jwks))
}

// KeyToJWKS creates a jwk.Set from the passed publicKey and sets the algorithm key in the jwk.Key to the passed jwa.SignatureAlgorithm
func KeyToJWKS(publicKey interface{}, alg jwa.SignatureAlgorithm) JWKS {
	key, err := jwk.New(publicKey)
	if err != nil {
		panic(err)
	}
	if err = jwk.AssignKeyID(key); err != nil {
		panic(err)
	}
	if err = key.Set(jwk.KeyUsageKey, string(jwk.ForSignature)); err != nil {
		panic(err)
	}
	if err = key.Set(jwk.AlgorithmKey, alg); err != nil {
		panic(err)
	}
	jwks := jwk.NewSet()
	jwks.Add(key)
	return JWKS{jwks}
}
