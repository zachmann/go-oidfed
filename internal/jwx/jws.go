package jwx

import (
	"crypto"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/pkg/errors"
	"github.com/vmihailenco/msgpack/v5"

	myjwk "github.com/go-oidfed/lib/pkg/jwk"
	"github.com/go-oidfed/lib/pkg/unixtime"
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
	return jws.Verify(p.RawJWT, jws.WithKeySet(keys.Set, jws.WithInferAlgorithmFromKey(true)))
}

// VerifyType verifies that the header typ has a certain value
func (p *ParsedJWT) VerifyType(typ string) bool {
	if p.Signatures() == nil {
		return false
	}
	head := p.Signatures()[0].ProtectedHeaders()
	headerTyp, typSet := head.Type()
	return typSet && headerTyp == typ
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
	k, err := jwk.Import(key)
	if err != nil {
		return nil, err
	}
	if err = jwk.AssignKeyID(k); err != nil {
		return nil, err
	}
	if headers == nil {
		headers = jws.NewHeaders()
	}
	keyID, _ := k.KeyID()
	if err = headers.Set(jws.KeyIDKey, keyID); err != nil {
		return nil, err
	}
	return jws.Sign(payload, jws.WithKey(signingAlg, key, jws.WithProtectedHeaders(headers)))
}

// GetExp returns the expiration of a jwt
func GetExp(bytes []byte) (exp unixtime.Unixtime, err error) {
	parsed, err := jwt.Parse(bytes)
	if err != nil {
		err = errors.WithStack(err)
		return
	}
	expT, _ := parsed.Expiration()
	return unixtime.Unixtime{Time: expT}, nil
}
