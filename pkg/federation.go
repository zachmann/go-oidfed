package pkg

import (
	"crypto"
	"time"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/pkg/errors"

	"github.com/zachmann/go-oidfed/pkg/cache"
)

// FederationEntity is a type for an entity participating in federations.
// It holds all relevant information about the federation entity and can be used to create
// an EntityConfiguration about it
type FederationEntity struct {
	EntityID              string
	Metadata              *Metadata
	AuthorityHints        []string
	ConfigurationLifetime int64
	*EntityStatementSigner
	jwks jwk.Set
}

// FederationLeaf is a type for a leaf entity and holds all relevant information about it; it can also be used to
// create an EntityConfiguration about it or to start OIDC flows
type FederationLeaf struct {
	FederationEntity
	TrustAnchors   TrustAnchors
	oidcROProducer *RequestObjectProducer
}

// NewFederationEntity creates a new FederationEntity with the passed properties
func NewFederationEntity(
	entityID string, authorityHints []string, metadata *Metadata,
	signer *EntityStatementSigner, configurationLifetime int64,
) (*FederationEntity, error) {
	if configurationLifetime <= 0 {
		configurationLifetime = defaultEntityConfigurationLifetime
	}
	return &FederationEntity{
		EntityID:              entityID,
		Metadata:              metadata,
		AuthorityHints:        authorityHints,
		EntityStatementSigner: signer,
		ConfigurationLifetime: configurationLifetime,
		jwks:                  signer.JWKS(),
	}, nil
}

// NewFederationLeaf creates a new FederationLeaf with the passed properties
func NewFederationLeaf(
	entityID string, authorityHints []string, trustAnchors TrustAnchors, metadata *Metadata,
	signer *EntityStatementSigner, configurationLifetime int64,
	oidcSigningKey crypto.Signer, oidcSigningAlg jwa.SignatureAlgorithm,
) (*FederationLeaf, error) {
	fed, err := NewFederationEntity(
		entityID, authorityHints, metadata, signer, configurationLifetime,
	)
	if err != nil {
		return nil, err
	}
	return &FederationLeaf{
		FederationEntity: *fed,
		TrustAnchors:     trustAnchors,
		oidcROProducer:   NewRequestObjectProducer(entityID, oidcSigningKey, oidcSigningAlg, 60),
	}, nil
}

// EntityConfigurationPayload returns an EntityStatementPayload for this FederationEntity
func (f FederationEntity) EntityConfigurationPayload() *EntityStatementPayload {
	now := time.Now()
	return &EntityStatementPayload{
		Issuer:         f.EntityID,
		Subject:        f.EntityID,
		IssuedAt:       Unixtime{now},
		ExpiresAt:      Unixtime{now.Add(time.Second * time.Duration(f.ConfigurationLifetime))},
		JWKS:           f.jwks,
		AuthorityHints: f.AuthorityHints,
		Metadata:       f.Metadata,
	}
}
func (f FederationEntity) EntityConfigurationJWT() ([]byte, error) {
	return f.EntityStatementSigner.JWT(f.EntityConfigurationPayload())
}

// SignEntityStatement creates a signed JWT for the given EntityStatementPayload; this function is intended to be
// used on TA/IA
func (f FederationEntity) SignEntityStatement(payload EntityStatementPayload) ([]byte, error) {
	return f.EntityStatementSigner.JWT(payload)
}

func (f FederationLeaf) RequestObjectProducer() *RequestObjectProducer {
	return f.oidcROProducer
}

func (f FederationLeaf) ResolveOPMetadata(issuer string) (*OpenIDProviderMetadata, error) {
	v, set := cache.Get(cache.Key(cache.KeyOPMetadata, issuer))
	if set {
		opm, ok := v.(*OpenIDProviderMetadata)
		if ok {
			return opm, nil
		}
	}
	tr := TrustResolver{
		TrustAnchors:   f.TrustAnchors,
		StartingEntity: issuer,
	}
	chains := tr.ResolveToValidChains()
	chains = chains.Filter(TrustChainsFilterMinPathLength)
	if len(chains) == 0 {
		return nil, errors.New("no trust chain found")
	}
	chain := chains[0]
	m, err := chain.Metadata()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	delta := time.Until(chain.ExpiresAt().Add(-time.Minute)) // we subtract a one-minute puffer
	if delta > 0 {
		cache.Set(cache.Key(cache.KeyOPMetadata, issuer), m.OpenIDProvider, delta)
	}
	return m.OpenIDProvider, nil
}
