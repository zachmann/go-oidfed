package pkg

import (
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

type mockOP struct {
	EntityID    string
	authorities []string
	jwks        jwk.Set
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
		jwks:                  jwx.KeyToJWKS(sk.Public(), jwa.ES512),
	}
	return o
}

func (op mockOP) EntityStatementPayload() EntityStatementPayload {
	now := time.Now()
	orgID := md5.Sum([]byte(op.EntityID))
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
				CommonMetadata: CommonMetadata{
					OrganizationName: fmt.Sprintf("Organization: %s", orgID[:2]),
				},
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
