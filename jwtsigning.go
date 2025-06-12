package oidfed

import (
	"crypto"
	"encoding/json"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/pkg/errors"

	"github.com/go-oidfed/lib/internal/jwx"
	"github.com/go-oidfed/lib/jwks"
	"github.com/go-oidfed/lib/oidfedconst"
)

// JWTSigner is an interface that can give signed jwts
type JWTSigner interface {
	JWT(i any) (jwt []byte, err error)
	JWKS() jwk.Set
}

// GeneralJWTSigner is a general jwt signer with no specific typ
type GeneralJWTSigner struct {
	key crypto.Signer
	alg jwa.SignatureAlgorithm
}

// NewGeneralJWTSigner creates a new GeneralJWTSigner
func NewGeneralJWTSigner(key crypto.Signer, alg jwa.SignatureAlgorithm) *GeneralJWTSigner {
	return &GeneralJWTSigner{
		key: key,
		alg: alg,
	}
}

// JWT returns a signed jwt representation of the passed data with the passed header type
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

// JWKS returns the jwks.JWKS used with this signer
func (s *GeneralJWTSigner) JWKS() jwks.JWKS {
	return jwks.KeyToJWKS(s.key.Public(), s.alg)
}

// Typed returns a TypedJWTSigner for the passed header type using the same crypto.Signer
func (s *GeneralJWTSigner) Typed(headerType string) *TypedJWTSigner {
	return &TypedJWTSigner{
		GeneralJWTSigner: s,
		HeaderType:       headerType,
	}
}

// EntityStatementSigner returns an EntityStatementSigner using the same crypto.Signer
func (s *GeneralJWTSigner) EntityStatementSigner() *EntityStatementSigner {
	return &EntityStatementSigner{s}
}

// TrustMarkSigner returns an TrustMarkSigner using the same crypto.Signer
func (s *GeneralJWTSigner) TrustMarkSigner() *TrustMarkSigner {
	return &TrustMarkSigner{s}
}

// TrustMarkDelegationSigner returns an TrustMarkDelegationSigner using the same
// crypto.Signer
func (s *GeneralJWTSigner) TrustMarkDelegationSigner() *TrustMarkDelegationSigner {
	return &TrustMarkDelegationSigner{s}
}

// ResolveResponseSigner returns an ResolveResponseSigner using the same crypto.Signer
func (s *GeneralJWTSigner) ResolveResponseSigner() *ResolveResponseSigner {
	return &ResolveResponseSigner{s}
}

// ResolveResponseSigner is a JWTSigner for oidfedconst.JWTTypeResolveResponse
type ResolveResponseSigner struct {
	*GeneralJWTSigner
}

// TrustMarkDelegationSigner is a JWTSigner for constants.
// JWTTypeTrustMarkDelegation
type TrustMarkDelegationSigner struct {
	*GeneralJWTSigner
}

// TrustMarkSigner is a JWTSigner for oidfedconst.JWTTypeTrustMark
type TrustMarkSigner struct {
	*GeneralJWTSigner
}

// EntityStatementSigner is a JWTSigner for oidfedconst.JWTTypeEntityStatement
type EntityStatementSigner struct {
	*GeneralJWTSigner
}

// JWT implements the JWTSigner interface
func (s ResolveResponseSigner) JWT(i any) (jwt []byte, err error) {
	return s.GeneralJWTSigner.JWT(i, oidfedconst.JWTTypeResolveResponse)
}

// JWT implements the JWTSigner interface
func (s TrustMarkDelegationSigner) JWT(i any) (jwt []byte, err error) {
	return s.GeneralJWTSigner.JWT(i, oidfedconst.JWTTypeTrustMarkDelegation)
}

// JWT implements the JWTSigner interface
func (s TrustMarkSigner) JWT(i any) (jwt []byte, err error) {
	return s.GeneralJWTSigner.JWT(i, oidfedconst.JWTTypeTrustMark)
}

// JWT implements the JWTSigner interface
func (s EntityStatementSigner) JWT(i any) (jwt []byte, err error) {
	return s.GeneralJWTSigner.JWT(i, oidfedconst.JWTTypeEntityStatement)
}

// NewEntityStatementSigner creates a new EntityStatementSigner
func NewEntityStatementSigner(key crypto.Signer, alg jwa.SignatureAlgorithm) *EntityStatementSigner {
	return &EntityStatementSigner{
		GeneralJWTSigner: NewGeneralJWTSigner(key, alg),
	}
}

// NewResolveResponseSigner creates a new ResolveResponseSigner
func NewResolveResponseSigner(key crypto.Signer, alg jwa.SignatureAlgorithm) *ResolveResponseSigner {
	return &ResolveResponseSigner{
		GeneralJWTSigner: NewGeneralJWTSigner(key, alg),
	}
}

// NewTrustMarkSigner creates a new TrustMarkSigner
func NewTrustMarkSigner(key crypto.Signer, alg jwa.SignatureAlgorithm) *TrustMarkSigner {
	return &TrustMarkSigner{
		GeneralJWTSigner: NewGeneralJWTSigner(key, alg),
	}
}

// NewTrustMarkDelegationSigner creates a new TrustMarkDelegationSigner
func NewTrustMarkDelegationSigner(key crypto.Signer, alg jwa.SignatureAlgorithm) *TrustMarkDelegationSigner {
	return &TrustMarkDelegationSigner{
		GeneralJWTSigner: NewGeneralJWTSigner(key, alg),
	}
}

// TypedJWTSigner is a JWTSigner for a specific header type
type TypedJWTSigner struct {
	*GeneralJWTSigner
	HeaderType string
}

// JWT implements the JWTSigner interface
func (s TypedJWTSigner) JWT(i any) (jwt []byte, err error) {
	return s.GeneralJWTSigner.JWT(i, s.HeaderType)
}
