package pkg

import (
	"crypto"
	"time"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
)

// FederationLeaf is a type for a leaf entity and holds all relevant information about it; it can also be used to
// create an EntityConfiguration about it or to start OIDC flows
type FederationLeaf struct {
	EntityID              string
	Metadata              *Metadata
	AuthorityHints        []string
	TrustAnchors          []string
	configurationLifetime int64
	key                   crypto.Signer
	alg                   jwa.SignatureAlgorithm
	jwks                  jwk.Set
}

// NewFederationLeaf creates a new FederationLeaf with the passed properties
func NewFederationLeaf(
	entityID string, authorityHints, trustAnchors []string, metadata *Metadata, privateSigningKey crypto.Signer,
	signingAlg jwa.SignatureAlgorithm, configurationLifetime int64,
) (*FederationLeaf, error) {
	if configurationLifetime <= 0 {
		configurationLifetime = defaultEntityConfigurationLifetime
	}
	key, err := jwk.New(privateSigningKey.Public())
	if err != nil {
		return nil, err
	}
	if err = jwk.AssignKeyID(key); err != nil {
		return nil, err
	}
	if err = key.Set(jwk.KeyUsageKey, jwk.ForSignature); err != nil {
		return nil, err
	}
	if err = key.Set(jwk.AlgorithmKey, signingAlg); err != nil {
		return nil, err
	}
	jwks := jwk.NewSet()
	jwks.Add(key)
	return &FederationLeaf{
		EntityID:              entityID,
		Metadata:              metadata,
		AuthorityHints:        authorityHints,
		TrustAnchors:          trustAnchors,
		key:                   privateSigningKey,
		alg:                   signingAlg,
		configurationLifetime: configurationLifetime,
		jwks:                  jwks,
	}, nil
}

// EntityConfiguration returns an EntityConfiguration for this FederationLeaf
func (f FederationLeaf) EntityConfiguration() *EntityConfiguration {
	now := time.Now().Unix()
	payload := EntityStatementPayload{
		Issuer:         f.EntityID,
		Subject:        f.EntityID,
		IssuedAt:       now,
		ExpiresAt:      now + f.configurationLifetime,
		JWKS:           f.jwks,
		AuthorityHints: f.AuthorityHints,
		Metadata:       f.Metadata,
	}
	return NewEntityConfiguration(payload, f.key, f.alg)
}
