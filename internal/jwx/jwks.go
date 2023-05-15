package jwx

import (
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
)

// KeyToJWKS creates a jwk.Set from the passed publicKey and sets the algorithm key in the jwk.Key to the passed jwa.SignatureAlgorithm
func KeyToJWKS(publicKey interface{}, alg jwa.SignatureAlgorithm) jwk.Set {
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
	return jwks
}
