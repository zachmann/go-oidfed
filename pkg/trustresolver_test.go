package pkg

import (
	"os"
	"testing"

	"github.com/luci/go-render/render"
)

func setup() {
	entityStatementObtainer = mockupData
}

func TestMain(m *testing.M) {
	setup()
	code := m.Run()
	os.Exit(code)
}

func TestTrustResolver_ResolveToValidChains(t *testing.T) {
	tests := []struct {
		name           string
		resolver       TrustResolver
		expectedChains TrustChains
	}{
		{
			name: "empty starting entity",
			resolver: TrustResolver{
				TrustAnchors: TrustAnchors{
					TrustAnchor{
						EntityID: ta1.EntityID,
						JWKS:     ta1.jwks,
					},
					TrustAnchor{
						EntityID: ta2.EntityID,
						JWKS:     ta2.jwks,
					},
				},
				StartingEntity: "",
			},
		},
		{
			name: "empty TAs",
			resolver: TrustResolver{
				TrustAnchors:   TrustAnchors{},
				StartingEntity: rp1.EntityID,
			},
		},
		{
			name: "rp1: ta1",
			resolver: TrustResolver{
				TrustAnchors: TrustAnchors{
					TrustAnchor{
						EntityID: ta1.EntityID,
						JWKS:     ta1.jwks,
					},
				},
				StartingEntity: rp1.EntityID,
			},
			expectedChains: ta1Chains,
		},
		{
			name: "rp1: ta2",
			resolver: TrustResolver{
				TrustAnchors: TrustAnchors{
					TrustAnchor{
						EntityID: ta2.EntityID,
						JWKS:     ta2.jwks,
					},
				},
				StartingEntity: rp1.EntityID,
			},
			expectedChains: ta2Chains,
		},
		{
			name: "rp1: ta1,ta2",
			resolver: TrustResolver{
				TrustAnchors: TrustAnchors{
					TrustAnchor{
						EntityID: ta1.EntityID,
						JWKS:     ta1.jwks,
					},
					TrustAnchor{
						EntityID: ta2.EntityID,
						JWKS:     ta2.jwks,
					},
				},
				StartingEntity: rp1.EntityID,
			},
			expectedChains: allChains,
		},
	}
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				chains := test.resolver.ResolveToValidChains()
				if !compareTrustChains(chains, test.expectedChains) {
					t.Errorf(
						"resolved TrustChains are not what we expected:\n\nResolved:\n%+v\n\nExpected:\n%+v\n\n",
						render.Render(chains), render.Render(test.expectedChains),
					)
				}
			},
		)
	}
}
