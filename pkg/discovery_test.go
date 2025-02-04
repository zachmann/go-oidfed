package pkg

import (
	"testing"

	"github.com/zachmann/go-oidfed/internal/utils"
)

func TestSimpleOPDiscoverer_Discover(t *testing.T) {
	tests := []struct {
		name         string
		trustAnchors TrustAnchors
		expectedOPs  []string
	}{
		{
			name: "ta1&ta2",
			trustAnchors: TrustAnchors{
				{EntityID: ta1.EntityID},
				{EntityID: ta2.EntityID},
			},
			expectedOPs: []string{
				op1.EntityID,
				op2.EntityID,
				op3.EntityID,
				proxy.EntityID,
			},
		},
		{
			name: "ta1",
			trustAnchors: TrustAnchors{
				{EntityID: ta1.EntityID},
			},
			expectedOPs: []string{
				op1.EntityID,
				op2.EntityID,
				op3.EntityID,
				proxy.EntityID,
			},
		},
		{
			name: "ta2",
			trustAnchors: TrustAnchors{
				{EntityID: ta1.EntityID},
			},
			expectedOPs: []string{
				op1.EntityID,
				op2.EntityID,
				op3.EntityID,
				proxy.EntityID,
			},
		},
		{
			name: "ia1",
			trustAnchors: TrustAnchors{
				{EntityID: ia1.EntityID},
			},
			expectedOPs: []string{
				op1.EntityID,
				op3.EntityID,
				proxy.EntityID,
			},
		},
		{
			name: "ia2",
			trustAnchors: TrustAnchors{
				{EntityID: ia2.EntityID},
			},
			expectedOPs: []string{
				op1.EntityID,
				op2.EntityID,
				op3.EntityID,
				proxy.EntityID,
			},
		},
	}
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				opMetadata := (&SimpleOPDiscoverer{}).Discover(test.trustAnchors...)
				if opMetadata == nil {
					t.Fatalf("opMetadata is nil")
				}
				if len(opMetadata) != len(test.expectedOPs) {
					t.Errorf("discovered OPs does not match expected OPs")
					t.Errorf("Expected: %+v", test.expectedOPs)
					t.Error("Discovered:")
					for _, op := range opMetadata {
						t.Error(op.Issuer)
					}
					t.FailNow()
				}
				for _, op := range opMetadata {
					if !utils.SliceContains(op.Issuer, test.expectedOPs) {
						t.Errorf("discovered OPs does not match expected OPs")
						t.Errorf("discovered: %+v", op.Issuer)
						t.Errorf("expected: %+v", test.expectedOPs)
						t.FailNow()
					}
				}
			},
		)
	}
}

func TestFilterableVerifiedChainsOPDiscoverer_Discover(t *testing.T) {
	tests := []struct {
		name         string
		filters      []OPDiscoveryFilter
		trustAnchors TrustAnchors
		expectedOPs  []string
	}{
		{
			name: "ta2",
			trustAnchors: TrustAnchors{
				{EntityID: ta2.EntityID},
			},
			expectedOPs: []string{
				op1.EntityID,
				op2.EntityID,
				op3.EntityID,
				proxy.EntityID,
			},
		},
		{
			name: "ta2, automatic",
			filters: []OPDiscoveryFilter{
				OPDiscoveryFilterAutomaticRegistration,
			},
			trustAnchors: TrustAnchors{
				{EntityID: ta2.EntityID},
			},
			expectedOPs: []string{
				op1.EntityID,
				op2.EntityID,
				op3.EntityID,
				proxy.EntityID,
			},
		},
		{
			name: "ta2, automatic, scopes",
			filters: []OPDiscoveryFilter{
				OPDiscoveryFilterAutomaticRegistration,
				OPDiscoveryFilterSupportedScopesIncludes("openid", "profile", "email"),
			},
			trustAnchors: TrustAnchors{
				{EntityID: ta2.EntityID},
			},
			expectedOPs: []string{
				op1.EntityID,
				op3.EntityID,
				proxy.EntityID,
			},
		},
		{
			name: "ia1",
			trustAnchors: TrustAnchors{
				{EntityID: ia1.EntityID},
			},
			expectedOPs: []string{
				op1.EntityID,
				op3.EntityID,
				proxy.EntityID,
			},
		},
		{
			name: "ia1, automatic, scope:address",
			filters: []OPDiscoveryFilter{
				OPDiscoveryFilterAutomaticRegistration,
				OPDiscoveryFilterSupportedScopesIncludes("address"),
			},
			trustAnchors: TrustAnchors{
				{EntityID: ia1.EntityID},
			},
			expectedOPs: []string{
				op1.EntityID,
			},
		},
		{
			name: "ia1, automatic, scope:address, grant_type:rt",
			filters: []OPDiscoveryFilter{
				OPDiscoveryFilterAutomaticRegistration,
				OPDiscoveryFilterSupportedScopesIncludes("address"),
				OPDiscoveryFilterSupportedGrantTypesIncludes("refresh_token"),
			},
			trustAnchors: TrustAnchors{
				{EntityID: ia1.EntityID},
			},
			expectedOPs: nil,
		},
	}
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				opMetadata := FilterableVerifiedChainsOPDiscoverer{Filters: test.filters}.Discover(test.trustAnchors...)
				if opMetadata == nil {
					if test.expectedOPs == nil {
						return
					}
					t.Fatalf("opMetadata is nil")
				}
				if len(opMetadata) != len(test.expectedOPs) {
					t.Fatalf("discovered OPs does not match expected OPs")
				}
				for _, op := range opMetadata {
					if !utils.SliceContains(op.Issuer, test.expectedOPs) {
						t.Fatalf("discovered OPs does not match expected OPs")
					}
				}
			},
		)
	}
}
