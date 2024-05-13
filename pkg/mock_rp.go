package pkg

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"

	"github.com/zachmann/go-oidfed/internal/jwx"
)

type mockRP struct {
	EntityID    string
	authorities []string
	jwks        jwk.Set
	signer      crypto.Signer
	signingAlg  jwa.SignatureAlgorithm
	metadata    *OpenIDRelyingPartyMetadata
}

func newMockRP(entityID string, metadata *OpenIDRelyingPartyMetadata) mockRP {
	sk, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		panic(err)
	}
	r := mockRP{
		EntityID:   entityID,
		metadata:   metadata,
		signer:     sk,
		signingAlg: jwa.ES512,
		jwks:       jwx.KeyToJWKS(sk.Public(), jwa.ES512),
	}
	return r
}

func (rp mockRP) EntityStatementPayload() EntityStatementPayload {
	now := time.Now()
	orgID := md5.Sum([]byte(rp.EntityID))
	payload := EntityStatementPayload{
		Issuer:         rp.EntityID,
		Subject:        rp.EntityID,
		IssuedAt:       Unixtime{now},
		ExpiresAt:      Unixtime{now.Add(time.Second * time.Duration(mockStmtLifetime))},
		JWKS:           rp.jwks,
		Audience:       "",
		AuthorityHints: rp.authorities,
		Metadata: &Metadata{
			FederationEntity: &FederationEntityMetadata{
				OrganizationName: fmt.Sprintf("Organization: %s", orgID[:2]),
			},
			RelyingParty: rp.metadata,
		},
	}
	return payload
}

func (rp mockRP) EntityConfiguration() *EntityConfiguration {
	return NewEntityConfiguration(rp.EntityStatementPayload(), rp.signer, rp.signingAlg)
}

func (rp mockRP) GetSubordinateInfo() mockSubordinateInfo {
	return mockSubordinateInfo{
		entityID: rp.EntityID,
		jwks:     rp.jwks,
	}
}

func (rp *mockRP) AddAuthority(authorityID string) {
	rp.authorities = append(rp.authorities, authorityID)
}
