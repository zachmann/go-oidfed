package pkg

import (
	"crypto"
	"time"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/pkg/errors"

	"github.com/zachmann/go-oidcfed/pkg/cache"
)

// FederationEntity is a type for an entity participating in federations.
// It holds all relevant information about the federation entity and can be used to create
// an EntityConfiguration about it
type FederationEntity struct {
	EntityID              string
	Metadata              *Metadata
	AuthorityHints        []string
	configurationLifetime int64
	federationKey         crypto.Signer
	alg                   jwa.SignatureAlgorithm
	jwks                  jwk.Set
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
	privateSigningKey crypto.Signer,
	signingAlg jwa.SignatureAlgorithm, configurationLifetime int64,
) (*FederationEntity, error) {
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
	return &FederationEntity{
		EntityID:              entityID,
		Metadata:              metadata,
		AuthorityHints:        authorityHints,
		federationKey:         privateSigningKey,
		alg:                   signingAlg,
		configurationLifetime: configurationLifetime,
		jwks:                  jwks,
	}, nil
}

// NewFederationLeaf creates a new FederationLeaf with the passed properties
func NewFederationLeaf(
	entityID string, authorityHints []string, trustAnchors TrustAnchors, metadata *Metadata,
	privateSigningKey crypto.Signer,
	signingAlg jwa.SignatureAlgorithm, configurationLifetime int64,
	oidcSigningKey crypto.Signer, oidcSigningAlg jwa.SignatureAlgorithm,
) (*FederationLeaf, error) {
	fed, err := NewFederationEntity(
		entityID, authorityHints, metadata, privateSigningKey, signingAlg, configurationLifetime,
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

// EntityConfiguration returns an EntityConfiguration for this FederationLeaf
func (f FederationEntity) EntityConfiguration() *EntityConfiguration {
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
	return NewEntityConfiguration(payload, f.federationKey, f.alg)
}

// SignEntityStatement creates a signed JWT for the given EntityStatementPayload; this function is intended to be
// used on TA/IA
func (f FederationEntity) SignEntityStatement(payload EntityStatementPayload) ([]byte, error) {
	c := NewEntityConfiguration(payload, f.federationKey, f.alg)
	return c.JWT()
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
	delta := time.Until(time.Unix(chain.ExpiresAt(), 0)) - time.Minute // we subtract a one-minute puffer
	if delta > 0 {
		cache.Set(cache.Key(cache.KeyOPMetadata, issuer), m.OpenIDProvider, delta)
	}
	return m.OpenIDProvider, nil
}
