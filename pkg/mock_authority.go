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

	"github.com/zachmann/go-oidfed/internal/jwx"
)

type mockAuthority struct {
	EntityID      string
	FetchEndpoint string
	ListEndpoint  string
	data          EntityStatementPayload
	signer        crypto.Signer
	signingAlg    jwa.SignatureAlgorithm
	subordinates  []mockSubordinateInfo
}

type mockSubordinateInfo struct {
	entityID string
	jwks     jwk.Set
}

type mockSubordinate interface {
	GetSubordinateInfo() mockSubordinateInfo
	AddAuthority(authorityID string)
}

func newMockAuthority(entityID string, data EntityStatementPayload) mockAuthority {
	sk, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		panic(err)
	}
	data.JWKS = jwx.KeyToJWKS(sk.Public(), jwa.ES512)
	data.Issuer = entityID
	data.Subject = entityID
	a := mockAuthority{
		EntityID:      entityID,
		FetchEndpoint: fmt.Sprintf("%s/fetch", entityID),
		ListEndpoint:  fmt.Sprintf("%s/list", entityID),
		data:          data,
		signer:        sk,
		signingAlg:    jwa.ES512,
	}
	if a.data.Metadata == nil {
		a.data.Metadata = &Metadata{}
	}
	if a.data.Metadata.FederationEntity == nil {
		a.data.Metadata.FederationEntity = &FederationEntityMetadata{}
	}
	a.data.Metadata.FederationEntity.OrganizationName = fmt.Sprintf("Organization %d", mathrand.Int()%100)
	a.data.Metadata.FederationEntity.FederationFetchEndpoint = a.FetchEndpoint
	a.data.Metadata.FederationEntity.FederationListEndpoint = a.ListEndpoint
	return a
}

func (a mockAuthority) EntityStatementPayload() EntityStatementPayload {
	now := time.Now()
	payload := a.data
	payload.IssuedAt = Unixtime{now}
	payload.ExpiresAt = Unixtime{now.Add(time.Second * time.Duration(mockStmtLifetime))}
	return payload
}

func (a mockAuthority) SubordinateEntityStatementPayload(subID string) EntityStatementPayload {
	now := time.Now()
	var jwks jwk.Set
	for _, s := range a.subordinates {
		if s.entityID == subID {
			jwks = s.jwks
		}
	}
	payload := EntityStatementPayload{
		Issuer:             a.EntityID,
		Subject:            subID,
		IssuedAt:           Unixtime{now},
		ExpiresAt:          Unixtime{now.Add(time.Second * time.Duration(mockStmtLifetime))},
		JWKS:               jwks,
		MetadataPolicy:     a.data.MetadataPolicy,
		MetadataPolicyCrit: a.data.MetadataPolicyCrit,
	}
	return payload
}

func (a mockAuthority) EntityConfiguration() *EntityConfiguration {
	return NewEntityConfiguration(a.EntityStatementPayload(), a.signer, a.signingAlg)
}

func (a mockAuthority) GetSubordinateInfo() mockSubordinateInfo {
	return mockSubordinateInfo{
		entityID: a.EntityID,
		jwks:     a.data.JWKS,
	}
}

func (a *mockAuthority) AddAuthority(authorityID string) {
	a.data.AuthorityHints = append(a.data.AuthorityHints, authorityID)
}

func (a *mockAuthority) RegisterSubordinate(s mockSubordinate) {
	info := s.GetSubordinateInfo()
	a.subordinates = append(a.subordinates, info)
	s.AddAuthority(a.EntityID)
}
