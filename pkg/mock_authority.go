package pkg

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	mathrand "math/rand"
	"time"

	"github.com/lestrrat-go/jwx/jwa"

	"github.com/zachmann/go-oidfed/pkg/jwk"
	"github.com/zachmann/go-oidfed/pkg/unixtime"
)

type mockAuthority struct {
	EntityID      string
	FetchEndpoint string
	ListEndpoint  string
	data          EntityStatementPayload
	*EntityStatementSigner
	subordinates []mockSubordinateInfo
}

type mockSubordinateInfo struct {
	entityID string
	jwks     jwk.JWKS
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
	data.JWKS = jwk.KeyToJWKS(sk.Public(), jwa.ES512)
	data.Issuer = entityID
	data.Subject = entityID
	a := mockAuthority{
		EntityID:              entityID,
		FetchEndpoint:         fmt.Sprintf("%s/fetch", entityID),
		ListEndpoint:          fmt.Sprintf("%s/list", entityID),
		data:                  data,
		EntityStatementSigner: NewEntityStatementSigner(sk, jwa.ES512),
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

func (a mockAuthority) EntityStatementPayload() *EntityStatementPayload {
	now := time.Now()
	payload := a.data
	payload.IssuedAt = unixtime.Unixtime{Time: now}
	payload.ExpiresAt = unixtime.Unixtime{Time: now.Add(time.Second * time.Duration(mockStmtLifetime))}
	return &payload
}

func (a mockAuthority) SubordinateEntityStatementPayload(subID string) EntityStatementPayload {
	now := time.Now()
	var jwks jwk.JWKS
	for _, s := range a.subordinates {
		if s.entityID == subID {
			jwks = s.jwks
		}
	}
	payload := EntityStatementPayload{
		Issuer:             a.EntityID,
		Subject:            subID,
		IssuedAt:           unixtime.Unixtime{Time: now},
		ExpiresAt:          unixtime.Unixtime{Time: now.Add(time.Second * time.Duration(mockStmtLifetime))},
		JWKS:               jwks,
		MetadataPolicy:     a.data.MetadataPolicy,
		MetadataPolicyCrit: a.data.MetadataPolicyCrit,
	}
	return payload
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
