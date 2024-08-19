package pkg

import (
	"crypto"
	"encoding/json"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/pkg/errors"

	"github.com/zachmann/go-oidfed/internal/jwx"
	"github.com/zachmann/go-oidfed/pkg/constants"
)

type JWTSigner interface {
	JWT(i any) (jwt []byte, err error)
	JWKS() jwk.Set
}

type GeneralJWTSigner struct {
	key crypto.Signer
	alg jwa.SignatureAlgorithm
}

func NewGeneralJWTSigner(key crypto.Signer, alg jwa.SignatureAlgorithm) *GeneralJWTSigner {
	return &GeneralJWTSigner{
		key: key,
		alg: alg,
	}
}

// JWT returns a signed jwt representation of the EntityConfiguration
func (s GeneralJWTSigner) JWT(i any, headerType string) (jwt []byte, err error) {
	if s.key == nil {
		return nil, errors.New("no signing key set")
	}
	var j []byte
	j, err = json.Marshal(i)
	if err != nil {
		return
	}
	jwt, err = jwx.SignWithType(j, headerType, s.alg, s.key)
	return
}
func (s *GeneralJWTSigner) JWKS() jwx.JWKS {
	return jwx.KeyToJWKS(s.key.Public(), s.alg)
}
func (s *GeneralJWTSigner) Typed(headerType string) *TypedJWTSigner {
	return &TypedJWTSigner{
		GeneralJWTSigner: s,
		HeaderType:       headerType,
	}
}
func (s *GeneralJWTSigner) EntityStatementSigner() *EntityStatementSigner {
	return &EntityStatementSigner{s}
}
func (s *GeneralJWTSigner) TrustMarkSigner() *TrustMarkSigner {
	return &TrustMarkSigner{s}
}
func (s *GeneralJWTSigner) TrustMarkDelegationSigner() *TrustMarkDelegationSigner {
	return &TrustMarkDelegationSigner{s}
}
func (s *GeneralJWTSigner) ResolveResponseSigner() *ResolveResponseSigner {
	return &ResolveResponseSigner{s}
}

type ResolveResponseSigner struct {
	*GeneralJWTSigner
}
type TrustMarkDelegationSigner struct {
	*GeneralJWTSigner
}
type TrustMarkSigner struct {
	*GeneralJWTSigner
}
type EntityStatementSigner struct {
	*GeneralJWTSigner
}

func (s ResolveResponseSigner) JWT(i any) (jwt []byte, err error) {
	return s.GeneralJWTSigner.JWT(i, constants.JWTTypeResolveResponse)
}
func (s TrustMarkDelegationSigner) JWT(i any) (jwt []byte, err error) {
	return s.GeneralJWTSigner.JWT(i, constants.JWTTypeTrustMarkDelegation)
}
func (s TrustMarkSigner) JWT(i any) (jwt []byte, err error) {
	return s.GeneralJWTSigner.JWT(i, constants.JWTTypeTrustMark)
}
func (s EntityStatementSigner) JWT(i any) (jwt []byte, err error) {
	return s.GeneralJWTSigner.JWT(i, constants.JWTTypeEntityStatement)
}

func NewEntityStatementSigner(key crypto.Signer, alg jwa.SignatureAlgorithm) *EntityStatementSigner {
	return &EntityStatementSigner{
		GeneralJWTSigner: NewGeneralJWTSigner(key, alg),
	}
}
func NewResolveResponseSigner(key crypto.Signer, alg jwa.SignatureAlgorithm) *ResolveResponseSigner {
	return &ResolveResponseSigner{
		GeneralJWTSigner: NewGeneralJWTSigner(key, alg),
	}
}
func NewTrustMarkSigner(key crypto.Signer, alg jwa.SignatureAlgorithm) *TrustMarkSigner {
	return &TrustMarkSigner{
		GeneralJWTSigner: NewGeneralJWTSigner(key, alg),
	}
}
func NewTrustMarkDelegationSigner(key crypto.Signer, alg jwa.SignatureAlgorithm) *TrustMarkDelegationSigner {
	return &TrustMarkDelegationSigner{
		GeneralJWTSigner: NewGeneralJWTSigner(key, alg),
	}
}

type TypedJWTSigner struct {
	*GeneralJWTSigner
	HeaderType string
}

func (s TypedJWTSigner) JWT(i any) (jwt []byte, err error) {
	return s.GeneralJWTSigner.JWT(i, s.HeaderType)
}
