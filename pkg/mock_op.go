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
)

type mockOP struct {
	EntityID    string
	authorities []string
	jwks        jwk.JWKS
	*EntityStatementSigner
	metadata *OpenIDProviderMetadata
}

func newMockOP(entityID string, metadata *OpenIDProviderMetadata) mockOP {
	sk, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		panic(err)
	}
	metadata.Issuer = entityID
	o := mockOP{
		EntityID:              entityID,
		metadata:              metadata,
		EntityStatementSigner: NewEntityStatementSigner(sk, jwa.ES512),
		jwks:                  jwk.KeyToJWKS(sk.Public(), jwa.ES512),
	}
	return o
}

func (op mockOP) EntityStatementPayload() EntityStatementPayload {
	now := time.Now()
	orgID := fmt.Sprintf("%x", md5.Sum([]byte(op.EntityID)))
	payload := EntityStatementPayload{
		Issuer:         op.EntityID,
		Subject:        op.EntityID,
		IssuedAt:       Unixtime{now},
		ExpiresAt:      Unixtime{now.Add(time.Second * time.Duration(mockStmtLifetime))},
		JWKS:           op.jwks,
		Audience:       "",
		AuthorityHints: op.authorities,
		Metadata: &Metadata{
			FederationEntity: &FederationEntityMetadata{
				OrganizationName: fmt.Sprintf("Organization: %s", orgID[:8]),
			},
			OpenIDProvider: op.metadata,
		},
	}
	return payload
}

func (op mockOP) GetSubordinateInfo() mockSubordinateInfo {
	return mockSubordinateInfo{
		entityID: op.EntityID,
		jwks:     op.jwks,
	}
}

func (op *mockOP) AddAuthority(authorityID string) {
	op.authorities = append(op.authorities, authorityID)
}
