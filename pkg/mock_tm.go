package pkg

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"

	"github.com/lestrrat-go/jwx/jwa"

	"github.com/zachmann/go-oidfed/internal/jwx"
)

type mockTMI struct {
	TrustMarkIssuer
	authorities []string
	jwks        jwx.JWKS
}

func (tmi *mockTMI) AddAuthority(authorityID string) {
	tmi.authorities = append(tmi.authorities, authorityID)
}

func newMockTrustMarkOwner(entityID string, ownedTrustMarks []OwnedTrustMark) *TrustMarkOwner {
	sk, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return NewTrustMarkOwner(entityID, NewTrustMarkDelegationSigner(sk, jwa.ES512), ownedTrustMarks)
}

func newMockTrustMarkIssuer(entityID string, trustMarkSpecs []TrustMarkSpec) mockTMI {
	sk, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		panic(err)
	}
	tmi := NewTrustMarkIssuer(entityID, NewTrustMarkSigner(sk, jwa.ES512), trustMarkSpecs)
	return mockTMI{
		TrustMarkIssuer: *tmi,
		jwks:            jwx.KeyToJWKS(tmi.key.Public(), tmi.alg),
	}
}

func (tmi mockTMI) GetSubordinateInfo() mockSubordinateInfo {
	return mockSubordinateInfo{
		entityID: tmi.EntityID,
		jwks:     tmi.jwks,
	}
}
