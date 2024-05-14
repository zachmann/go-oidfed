package jwx

import (
	"crypto"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/pkg/errors"

	"github.com/zachmann/go-oidfed/internal/utils"
)

// VerifyWithSet uses a jwk.Set to verify a *jws.Message, returning the decoded payload or an error
func VerifyWithSet(msg *jws.Message, keys jwk.Set) ([]byte, error) {
	var alg jwa.SignatureAlgorithm
	var kid string
	if msg.Signatures() != nil {
		head := msg.Signatures()[0].ProtectedHeaders()
		alg = head.Algorithm()
		kid = head.KeyID()
	}
	buf, err := msg.MarshalJSON()
	if err != nil {
		return nil, err
	}
	if alg == "" && kid == "" {
		return jws.VerifySet(buf, keys)
	}
	for i := 0; i < keys.Len(); i++ {
		k, ok := keys.Get(i)
		if !ok {
			continue
		}
		if !utils.StringsEqualIfSet(alg.String(), k.Algorithm()) {
			continue
		}
		if !utils.StringsEqualIfSet(kid, k.KeyID()) {
			continue
		}
		pay, err := jws.Verify(buf, alg, k)
		if err == nil {
			return pay, nil
		}
	}
	return nil, errors.New(`failed to verify message with any of the keys in the jwk.Set object`)
}

// SignEntityStatement creates a signed JWT of the 'entity-statement+jwt' type for the passed payload using the
// passed crypto.Signer with the passed jwa.SignatureAlgorithm
func SignEntityStatement(payload []byte, signingAlg jwa.SignatureAlgorithm, key crypto.Signer) ([]byte, error) {
	headers := jws.NewHeaders()
	if err := headers.Set(jws.TypeKey, "entity-statement+jwt"); err != nil {
		return nil, err
	}
	return SignPayload(payload, signingAlg, key, headers)
}

// SignPayload signs a payload with the passed properties and adds the kid to the jwt header
func SignPayload(payload []byte, signingAlg jwa.SignatureAlgorithm, key crypto.Signer, headers jws.Headers) (
	[]byte,
	error,
) {
	k, err := jwk.New(key)
	if err != nil {
		return nil, err
	}
	if err = jwk.AssignKeyID(k); err != nil {
		return nil, err
	}
	if headers == nil {
		headers = jws.NewHeaders()
	}
	if err = headers.Set(jws.KeyIDKey, k.KeyID()); err != nil {
		return nil, err
	}
	return jws.Sign(payload, signingAlg, key, jws.WithHeaders(headers))
}
