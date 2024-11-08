package jwx

import (
	"crypto"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/pkg/errors"
	"github.com/vmihailenco/msgpack/v5"

	"github.com/zachmann/go-oidfed/internal/utils"
	myjwk "github.com/zachmann/go-oidfed/pkg/jwk"
)

// ParsedJWT is a type extending jws.Message by holding the original jwt
type ParsedJWT struct {
	RawJWT []byte
	*jws.Message
}

// MarshalMsgpack implements the msgpack.Marshaler interface
func (p ParsedJWT) MarshalMsgpack() ([]byte, error) {
	return msgpack.Marshal(p.RawJWT)
}

// UnmarshalMsgpack implements the msgpack.Unmarshaler interface
func (p *ParsedJWT) UnmarshalMsgpack(data []byte) error {
	if err := msgpack.Unmarshal(data, &p.RawJWT); err != nil {
		return errors.WithStack(err)
	}
	pp, err := Parse(p.RawJWT)
	if err != nil {
		return err
	}
	*p = *pp
	return nil
}

// Parse parses a jwt and returns a ParsedJWT
func Parse(data []byte) (*ParsedJWT, error) {
	m, err := jws.Parse(data)
	return &ParsedJWT{
		RawJWT:  data,
		Message: m,
	}, errors.WithStack(err)
}

// VerifyWithSet uses a jwk.Set to verify a *jws.Message, returning the decoded payload or an error
func (p *ParsedJWT) VerifyWithSet(keys myjwk.JWKS) ([]byte, error) {
	if p == nil || p.Message == nil {
		return nil, errors.New("jws.Verify: missing message")
	}
	if keys.Set == nil || keys.Len() == 0 {
		return nil, errors.New("jwt verify: no keys passed")
	}
	var alg jwa.SignatureAlgorithm
	var kid string
	if p.Signatures() != nil {
		head := p.Signatures()[0].ProtectedHeaders()
		alg = head.Algorithm()
		kid = head.KeyID()
	}
	if alg == "" && kid == "" {
		return jws.VerifySet(p.RawJWT, keys.Set)
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
		pay, err := jws.Verify(p.RawJWT, alg, k)
		if err == nil {
			return pay, nil
		}
	}
	return nil, errors.New(`failed to verify message with any of the keys in the jwk.Set object`)
}

// VerifyType verifies that the header typ has a certain value
func (p *ParsedJWT) VerifyType(typ string) bool {
	if p.Signatures() == nil {
		return false
	}
	head := p.Signatures()[0].ProtectedHeaders()
	return head.Type() == typ
}

// SignWithType creates a signed JWT of the passed type for the passed payload using the
// passed crypto.Signer with the passed jwa.SignatureAlgorithm
func SignWithType(payload []byte, typ string, signingAlg jwa.SignatureAlgorithm, key crypto.Signer) ([]byte, error) {
	headers := jws.NewHeaders()
	if err := headers.Set(jws.TypeKey, typ); err != nil {
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
