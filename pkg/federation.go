package pkg

import (
	"crypto"
	"time"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/pkg/errors"

	"github.com/zachmann/go-oidcfed/pkg/cache"
)

// FederationLeaf is a type for a leaf entity and holds all relevant information about it; it can also be used to
// create an EntityConfiguration about it or to start OIDC flows
type FederationLeaf struct {
	EntityID              string
	Metadata              *Metadata
	AuthorityHints        []string
	TrustAnchors          TrustAnchors
	configurationLifetime int64
	federationKey         crypto.Signer
	alg                   jwa.SignatureAlgorithm
	jwks                  jwk.Set
	oidcROProducer        *RequestObjectProducer
}

// NewFederationLeaf creates a new FederationLeaf with the passed properties
func NewFederationLeaf(
	entityID string, authorityHints []string, trustAnchors TrustAnchors, metadata *Metadata,
	privateSigningKey crypto.Signer,
	signingAlg jwa.SignatureAlgorithm, configurationLifetime int64,
	oidcSigningKey crypto.Signer, oidcSigningAlg jwa.SignatureAlgorithm,
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
		federationKey:         privateSigningKey,
		alg:                   signingAlg,
		configurationLifetime: configurationLifetime,
		jwks:                  jwks,
		oidcROProducer:        NewRequestObjectProducer(entityID, oidcSigningKey, oidcSigningAlg, 60),
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
	return NewEntityConfiguration(payload, f.federationKey, f.alg)
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
	delta := time.Unix(chain.ExpiresAt(), 0).Sub(time.Now()) - time.Minute // we subtract a one-minute puffer
	if delta > 0 {
		cache.Set(cache.Key(cache.KeyOPMetadata, issuer), m.OpenIDProvider, delta)
	}
	return m.OpenIDProvider, nil
}
