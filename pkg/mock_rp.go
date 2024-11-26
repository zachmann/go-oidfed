package pkg

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/jwa"

	"github.com/zachmann/go-oidfed/pkg/jwk"
	"github.com/zachmann/go-oidfed/pkg/unixtime"
)

type mockRP struct {
	EntityID    string
	authorities []string
	jwks        jwk.JWKS
	*EntityStatementSigner
	metadata *OpenIDRelyingPartyMetadata
}

func newMockRP(entityID string, metadata *OpenIDRelyingPartyMetadata) mockRP {
	sk, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		panic(err)
	}
	r := mockRP{
		EntityID:              entityID,
		metadata:              metadata,
		EntityStatementSigner: NewEntityStatementSigner(sk, jwa.ES512),
		jwks:                  jwk.KeyToJWKS(sk.Public(), jwa.ES512),
	}
	return r
}

func (rp mockRP) EntityStatementPayload() EntityStatementPayload {
	now := time.Now()
	orgID := fmt.Sprintf("%x", md5.Sum([]byte(rp.EntityID)))
	payload := EntityStatementPayload{
		Issuer:         rp.EntityID,
		Subject:        rp.EntityID,
		IssuedAt:       unixtime.Unixtime{Time: now},
		ExpiresAt:      unixtime.Unixtime{Time: now.Add(time.Second * time.Duration(mockStmtLifetime))},
		JWKS:           rp.jwks,
		Audience:       "",
		AuthorityHints: rp.authorities,
		Metadata: &Metadata{
			FederationEntity: &FederationEntityMetadata{
				OrganizationName: fmt.Sprintf("Organization: %s", orgID[:8]),
			},
			RelyingParty: rp.metadata,
		},
	}
	return payload
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
