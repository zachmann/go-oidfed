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

type mockProxy struct {
	EntityID    string
	authorities []string
	jwks        jwk.Set
	*EntityStatementSigner
	rpMetadata *OpenIDRelyingPartyMetadata
	opMetadata *OpenIDProviderMetadata
}

func newMockProxy(
	entityID string,
	rp *OpenIDRelyingPartyMetadata, op *OpenIDProviderMetadata,
) mockProxy {
	sk, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		panic(err)
	}
	op.Issuer = entityID
	p := mockProxy{
		EntityID:              entityID,
		rpMetadata:            rp,
		opMetadata:            op,
		EntityStatementSigner: NewEntityStatementSigner(sk, jwa.ES512),
		jwks:                  jwx.KeyToJWKS(sk.Public(), jwa.ES512),
	}
	return p
}

func (proxy mockProxy) EntityStatementPayload() EntityStatementPayload {
	now := time.Now()
	orgID := md5.Sum([]byte(proxy.EntityID))
	common := CommonMetadata{
		OrganizationName: fmt.Sprintf("Organization: %s", orgID[:2]),
	}
	proxy.rpMetadata.CommonMetadata = common
	proxy.opMetadata.CommonMetadata = common
	payload := EntityStatementPayload{
		Issuer:         proxy.EntityID,
		Subject:        proxy.EntityID,
		IssuedAt:       Unixtime{now},
		ExpiresAt:      Unixtime{now.Add(time.Second * time.Duration(mockStmtLifetime))},
		JWKS:           proxy.jwks,
		Audience:       "",
		AuthorityHints: proxy.authorities,
		Metadata: &Metadata{
			FederationEntity: &FederationEntityMetadata{
				CommonMetadata: common,
			},
			RelyingParty:   proxy.rpMetadata,
			OpenIDProvider: proxy.opMetadata,
		},
	}
	return payload
}

func (proxy mockProxy) GetSubordinateInfo() mockSubordinateInfo {
	return mockSubordinateInfo{
		entityID: proxy.EntityID,
		jwks:     proxy.jwks,
	}
}

func (proxy *mockProxy) AddAuthority(authorityID string) {
	proxy.authorities = append(proxy.authorities, authorityID)
}
