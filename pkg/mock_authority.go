package pkg

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	mathrand "math/rand"
	"time"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"

	"github.com/zachmann/go-oidcfed/internal/jwx"
)

type mockAuthority struct {
	EntityID      string
	FetchEndpoint string
	authorities   []string
	subordinates  []mockSubordinateInfo
	jwks          jwk.Set
	signer        crypto.Signer
	signingAlg    jwa.SignatureAlgorithm
	policies      *MetadataPolicies
}

type mockSubordinateInfo struct {
	entityID string
	jwks     jwk.Set
}

type mockSubordinate interface {
	GetSubordinateInfo() mockSubordinateInfo
	AddAuthority(authorityID string)
}

func newMockAuthority(entityID string, metadataPolicies *MetadataPolicies) mockAuthority {
	sk, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		panic(err)
	}
	a := mockAuthority{
		EntityID:      entityID,
		FetchEndpoint: fmt.Sprintf("%s/fetch", entityID),
		policies:      metadataPolicies,
		signer:        sk,
		signingAlg:    jwa.ES512,
		jwks:          jwx.KeyToJWKS(sk.Public(), jwa.ES512),
	}
	return a
}

func (a mockAuthority) EntityStatementPayload() EntityStatementPayload {
	now := time.Now().Unix()
	payload := EntityStatementPayload{
		Issuer:         a.EntityID,
		Subject:        a.EntityID,
		IssuedAt:       now,
		ExpiresAt:      now + mockStmtLifetime,
		JWKS:           a.jwks,
		Audience:       "",
		AuthorityHints: a.authorities,
		MetadataPolicy: a.policies,
		Metadata: &Metadata{
			FederationEntity: &FederationEntityMetadata{
				OrganizationName:        fmt.Sprintf("Organization %d", mathrand.Int()%100),
				FederationFetchEndpoint: a.FetchEndpoint,
			},
		},
	}
	return payload
}

func (a mockAuthority) SubordinateEntityStatementPayload(subID string) EntityStatementPayload {
	now := time.Now().Unix()
	var jwks jwk.Set
	for _, s := range a.subordinates {
		if s.entityID == subID {
			jwks = s.jwks
		}
	}
	payload := EntityStatementPayload{
		Issuer:         a.EntityID,
		Subject:        subID,
		IssuedAt:       now,
		ExpiresAt:      now + mockStmtLifetime,
		JWKS:           jwks,
		MetadataPolicy: a.policies,
	}
	return payload
}

func (a mockAuthority) EntityConfiguration() *EntityConfiguration {
	return NewEntityConfiguration(a.EntityStatementPayload(), a.signer, a.signingAlg)
}

func (a mockAuthority) GetSubordinateInfo() mockSubordinateInfo {
	return mockSubordinateInfo{
		entityID: a.EntityID,
		jwks:     a.jwks,
	}
}

func (a *mockAuthority) AddAuthority(authorityID string) {
	a.authorities = append(a.authorities, authorityID)
}

func (a *mockAuthority) RegisterSubordinate(s mockSubordinate) {
	info := s.GetSubordinateInfo()
	a.subordinates = append(a.subordinates, info)
	s.AddAuthority(a.EntityID)
}
