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

	"github.com/zachmann/go-oidcfed/internal/jwx"
)

type mockOP struct {
	EntityID    string
	authorities []string
	jwks        jwk.Set
	signer      crypto.Signer
	signingAlg  jwa.SignatureAlgorithm
	metadata    *OpenIDProviderMetadata
}

func newMockOP(entityID string, metadata *OpenIDProviderMetadata) mockOP {
	sk, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		panic(err)
	}
	metadata.Issuer = entityID
	o := mockOP{
		EntityID:   entityID,
		metadata:   metadata,
		signer:     sk,
		signingAlg: jwa.ES512,
		jwks:       jwx.KeyToJWKS(sk.Public(), jwa.ES512),
	}
	return o
}

func (op mockOP) EntityStatementPayload() EntityStatementPayload {
	now := time.Now().Unix()
	orgID := md5.Sum([]byte(op.EntityID))
	payload := EntityStatementPayload{
		Issuer:         op.EntityID,
		Subject:        op.EntityID,
		IssuedAt:       now,
		ExpiresAt:      now + mockStmtLifetime,
		JWKS:           op.jwks,
		Audience:       "",
		AuthorityHints: op.authorities,
		Metadata: &Metadata{
			FederationEntity: &FederationEntityMetadata{
				OrganizationName: fmt.Sprintf("Organization: %s", orgID[:2]),
			},
			OpenIDProvider: op.metadata,
		},
	}
	return payload
}

func (op mockOP) EntityConfiguration() *EntityConfiguration {
	return NewEntityConfiguration(op.EntityStatementPayload(), op.signer, op.signingAlg)
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
