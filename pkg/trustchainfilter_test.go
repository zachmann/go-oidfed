package pkg

import (
	"testing"

	arrops "github.com/adam-hanna/arrayOperations"
)

var rp1 = newMockRP(
	"https://rp1.example.com",
	&OpenIDRelyingPartyMetadata{ClientRegistrationTypes: []string{ClientRegistrationTypeAutomatic}},
)

var op1 = newMockOP(
	"https://op1.example.com",
	&OpenIDProviderMetadata{
		ClientRegistrationTypesSupported: []string{ClientRegistrationTypeAutomatic},
		ScopesSupported: []string{
			"openid",
			"profile",
			"email",
			"address",
		},
	},
)
var op2 = newMockOP(
	"https://op2.example.com",
	&OpenIDProviderMetadata{
		ClientRegistrationTypesSupported: []string{ClientRegistrationTypeAutomatic},
		ScopesSupported: []string{
			"openid",
			"profile",
		},
	},
)
var op3 = newMockOP(
	"https://op3.example.com",
	&OpenIDProviderMetadata{
		ClientRegistrationTypesSupported: []string{ClientRegistrationTypeAutomatic},
		ScopesSupported: []string{
			"openid",
			"profile",
			"email",
		},
	},
)

var ia1 = newMockAuthority("https://ia.example.com", nil, nil)
var ia2 = newMockAuthority(
	"https://ia.example.org", &MetadataPolicies{
		RelyingParty: MetadataPolicy{
			"contacts": MetadataPolicyEntry{
				PolicyOperatorAdd: "ia@example.org",
			},
		},
	},
	nil,
)
var ta1 = newMockAuthority("https://ta.example.com", nil, nil)
var ta2 = newMockAuthority(
	"https://ta.foundation.example.org", &MetadataPolicies{
		RelyingParty: MetadataPolicy{
			"contacts": MetadataPolicyEntry{
				PolicyOperatorAdd: "ta@foundation.example.org",
			},
			"client_registration_types": MetadataPolicyEntry{
				PolicyOperatorEssential: true,
			},
		},
	},
	nil,
)
var ta2WithRemove = newMockAuthority(
	"https://ta.foundation.example.org/remove", &MetadataPolicies{
		RelyingParty: MetadataPolicy{
			"contacts": MetadataPolicyEntry{
				PolicyOperatorAdd: "ta@foundation.example.org",
			},
			"client_registration_types": MetadataPolicyEntry{
				PolicyOperatorEssential: true,
				"remove":                "explicit",
			},
		},
	},
	nil,
)
var ta2WithRemoveCrit = newMockAuthority(
	"https://ta.foundation.example.org/remove/crit", &MetadataPolicies{
		RelyingParty: MetadataPolicy{
			"contacts": MetadataPolicyEntry{
				PolicyOperatorAdd: "ta@foundation.example.org",
			},
			"client_registration_types": MetadataPolicyEntry{
				PolicyOperatorEssential: true,
				"remove":                "explicit",
			},
		},
	},
	[]PolicyOperatorName{"remove"},
)

func init() {
	ia1.RegisterSubordinate(&rp1)
	ia2.RegisterSubordinate(&rp1)
	ia1.RegisterSubordinate(&op1)
	ia2.RegisterSubordinate(&op1)
	ia1.RegisterSubordinate(&op3)
	ia2.RegisterSubordinate(&op2)
	ia2.RegisterSubordinate(&ia1)
	ta1.RegisterSubordinate(&ia1)
	ta1.RegisterSubordinate(&ia2)
	ta2.RegisterSubordinate(&ia2)
	ta2WithRemove.RegisterSubordinate(&ia2)
	ta2WithRemoveCrit.RegisterSubordinate(&ia2)

	mockupData.AddRP(rp1)
	mockupData.AddOP(op1)
	mockupData.AddOP(op2)
	mockupData.AddOP(op3)
	mockupData.AddAuthority(ia1)
	mockupData.AddAuthority(ia2)
	mockupData.AddAuthority(ta1)
	mockupData.AddAuthority(ta2)
}

var chainRPIA1TA1 = TrustChain{
	{EntityStatementPayload: rp1.EntityStatementPayload()},
	{EntityStatementPayload: ia1.SubordinateEntityStatementPayload(rp1.EntityID)},
	{EntityStatementPayload: ta1.SubordinateEntityStatementPayload(ia1.EntityID)},
}

var chainRPIA2TA1 = TrustChain{
	{EntityStatementPayload: rp1.EntityStatementPayload()},
	{EntityStatementPayload: ia2.SubordinateEntityStatementPayload(rp1.EntityID)},
	{EntityStatementPayload: ta1.SubordinateEntityStatementPayload(ia2.EntityID)},
}

var chainRPIA1IA2TA1 = TrustChain{
	{EntityStatementPayload: rp1.EntityStatementPayload()},
	{EntityStatementPayload: ia1.SubordinateEntityStatementPayload(rp1.EntityID)},
	{EntityStatementPayload: ia2.SubordinateEntityStatementPayload(ia1.EntityID)},
	{EntityStatementPayload: ta1.SubordinateEntityStatementPayload(ia2.EntityID)},
}

var chainRPIA2TA2 = TrustChain{
	{EntityStatementPayload: rp1.EntityStatementPayload()},
	{EntityStatementPayload: ia2.SubordinateEntityStatementPayload(rp1.EntityID)},
	{EntityStatementPayload: ta2.SubordinateEntityStatementPayload(ia2.EntityID)},
}
var chainRPIA2TA2WithRemove = TrustChain{
	{EntityStatementPayload: rp1.EntityStatementPayload()},
	{EntityStatementPayload: ia2.SubordinateEntityStatementPayload(rp1.EntityID)},
	{EntityStatementPayload: ta2WithRemove.SubordinateEntityStatementPayload(ia2.EntityID)},
}
var chainRPIA2TA2WithRemoveCrit = TrustChain{
	{EntityStatementPayload: rp1.EntityStatementPayload()},
	{EntityStatementPayload: ia2.SubordinateEntityStatementPayload(rp1.EntityID)},
	{EntityStatementPayload: ta2WithRemoveCrit.SubordinateEntityStatementPayload(ia2.EntityID)},
}

var chainRPIA1IA2TA2 = TrustChain{
	{EntityStatementPayload: rp1.EntityStatementPayload()},
	{EntityStatementPayload: ia1.SubordinateEntityStatementPayload(rp1.EntityID)},
	{EntityStatementPayload: ia2.SubordinateEntityStatementPayload(ia1.EntityID)},
	{EntityStatementPayload: ta2.SubordinateEntityStatementPayload(ia2.EntityID)},
}

var allChains = TrustChains{
	chainRPIA1TA1,
	chainRPIA1IA2TA1,
	chainRPIA1IA2TA2,
	chainRPIA2TA2,
	chainRPIA2TA1,
}
var ia1Chains = TrustChains{
	chainRPIA1TA1,
	chainRPIA1IA2TA1,
	chainRPIA1IA2TA2,
}
var ia2Chains = TrustChains{
	chainRPIA2TA2,
	chainRPIA2TA1,
}
var ta1Chains = TrustChains{
	chainRPIA1TA1,
	chainRPIA1IA2TA1,
	chainRPIA2TA1,
}
var ta2Chains = TrustChains{
	chainRPIA1IA2TA2,
	chainRPIA2TA2,
}

func compareTrustChains(a, b TrustChains) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	if len(a) != len(b) {
		return false
	}
	aIssChains := make([]string, len(a))
	bIssChains := make([]string, len(b))
	for i, aa := range a {
		var issChain string
		for _, e := range aa {
			issChain += "->" + e.Issuer
		}
		aIssChains[i] = issChain
	}
	for i, bb := range b {
		var issChain string
		for _, e := range bb {
			issChain += "->" + e.Issuer
		}
		bIssChains[i] = issChain
	}
	return len(arrops.Difference(aIssChains, bIssChains)) == 0
}

func TestTrustChainFiltersTrustAnchor(t *testing.T) {
	tests := []struct {
		name     string
		filter   TrustChainsFilter
		in       TrustChains
		expected TrustChains
	}{
		{
			name:     "all chains -> ta2",
			filter:   TrustChainsFilterTrustAnchor(ta2.EntityID),
			in:       allChains,
			expected: ta2Chains,
		},
		{
			name:     "all chains -> ta1",
			filter:   TrustChainsFilterTrustAnchor(ta1.EntityID),
			in:       allChains,
			expected: ta1Chains,
		},
		{
			name:     "ta1 chains -> ta1",
			filter:   TrustChainsFilterTrustAnchor(ta1.EntityID),
			in:       ta1Chains,
			expected: ta1Chains,
		},
		{
			name:     "ta1 chains -> ta2",
			filter:   TrustChainsFilterTrustAnchor(ta2.EntityID),
			in:       ta1Chains,
			expected: nil,
		},
		{
			name:     "all chains -> unknown",
			filter:   TrustChainsFilterTrustAnchor("https://ta.unknown.com"),
			in:       allChains,
			expected: nil,
		},
		{
			name:   "ia1 chains -> ta1",
			filter: TrustChainsFilterTrustAnchor(ta1.EntityID),
			in:     ia1Chains,
			expected: TrustChains{
				chainRPIA1TA1,
				chainRPIA1IA2TA1,
			},
		},
		{
			name:   "ia1 chains -> ta2",
			filter: TrustChainsFilterTrustAnchor(ta2.EntityID),
			in:     ia1Chains,
			expected: TrustChains{
				chainRPIA1IA2TA2,
			},
		},
	}
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				filtered := test.filter.Filter(test.in)
				if !compareTrustChains(filtered, test.expected) {
					t.Errorf(
						"filtered TrustChains are not what we expected:\n\nFiltered:\n%+v\n\nExpected:\n%+v\n\n",
						filtered, test.expected,
					)
				}
			},
		)
	}
}

func TestTrustChainFiltersMinPath(t *testing.T) {
	filter := TrustChainsFilterMinPathLength
	tests := []struct {
		name     string
		in       TrustChains
		expected TrustChains
	}{
		{
			name: "all chains",
			in:   allChains,
			expected: TrustChains{
				chainRPIA1TA1,
				chainRPIA2TA2,
				chainRPIA2TA1,
			},
		},
		{
			name: "ta1 chains",
			in:   ta1Chains,
			expected: TrustChains{
				chainRPIA1TA1,
				chainRPIA2TA1,
			},
		},
		{
			name: "ta2 chains",
			in:   ta2Chains,
			expected: TrustChains{
				chainRPIA2TA2,
			},
		},
		{
			name: "ia1 chains",
			in:   ia1Chains,
			expected: TrustChains{
				chainRPIA1TA1,
			},
		},
		{
			name: "ia2 chains",
			in:   ia2Chains,
			expected: TrustChains{
				chainRPIA2TA2,
				chainRPIA2TA1,
			},
		},
	}
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				filtered := filter.Filter(test.in)
				if !compareTrustChains(filtered, test.expected) {
					t.Errorf(
						"filtered TrustChains are not what we expected:\n\nFiltered:\n%+v\n\nExpected:\n%+v\n\n",
						filtered, test.expected,
					)
				}
			},
		)
	}
}

func TestTrustChainFiltersPathLength(t *testing.T) {
	tests := []struct {
		name     string
		filter   TrustChainsFilter
		in       TrustChains
		expected TrustChains
	}{
		{
			name:     "all chains -> 5",
			filter:   TrustChainsFilterMaxPathLength(5),
			in:       allChains,
			expected: allChains,
		},
		{
			name:     "all chains -> 4",
			filter:   TrustChainsFilterMaxPathLength(4),
			in:       allChains,
			expected: allChains,
		},
		{
			name:   "all chains -> 3",
			filter: TrustChainsFilterMaxPathLength(3),
			in:     allChains,
			expected: TrustChains{
				chainRPIA2TA2,
				chainRPIA2TA1,
				chainRPIA1TA1,
			},
		},
		{
			name:     "all chains -> 2",
			filter:   TrustChainsFilterMaxPathLength(2),
			in:       allChains,
			expected: nil,
		},
	}
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				filtered := test.filter.Filter(test.in)
				if !compareTrustChains(filtered, test.expected) {
					t.Errorf(
						"filtered TrustChains are not what we expected:\n\nFiltered:\n%+v\n\nExpected:\n%+v\n\n",
						filtered, test.expected,
					)
				}
			},
		)
	}
}

func TestTrustChains_Filter(t *testing.T) {
	tests := []struct {
		name     string
		filter   []TrustChainsFilter
		in       TrustChains
		expected TrustChains
	}{
		{
			name: "all chains -> ta2 min",
			filter: []TrustChainsFilter{
				TrustChainsFilterTrustAnchor(ta2.EntityID),
				TrustChainsFilterMinPathLength,
			},
			in: allChains,
			expected: TrustChains{
				chainRPIA2TA2,
			},
		},
		{
			name: "all chains -> min ta2",
			filter: []TrustChainsFilter{
				TrustChainsFilterMinPathLength,
				TrustChainsFilterTrustAnchor(ta2.EntityID),
			},
			in: allChains,
			expected: TrustChains{
				chainRPIA2TA2,
			},
		},
		{
			name: "all chains -> ta1 min",
			filter: []TrustChainsFilter{
				TrustChainsFilterTrustAnchor(ta1.EntityID),
				TrustChainsFilterMinPathLength,
			},
			in: allChains,
			expected: TrustChains{
				chainRPIA1TA1,
				chainRPIA2TA1,
			},
		},
		{
			name: "ta1 chains -> ta1 min",
			filter: []TrustChainsFilter{
				TrustChainsFilterTrustAnchor(ta1.EntityID),
				TrustChainsFilterMinPathLength,
			},
			in: ta1Chains,
			expected: TrustChains{
				chainRPIA1TA1,
				chainRPIA2TA1,
			},
		},
		{
			name: "ta1 chains -> ta2 min",
			filter: []TrustChainsFilter{
				TrustChainsFilterTrustAnchor(ta2.EntityID),
				TrustChainsFilterMinPathLength,
			},
			in:       ta1Chains,
			expected: nil,
		},
		{
			name: "all chains -> unknown min",
			filter: []TrustChainsFilter{
				TrustChainsFilterTrustAnchor("https://ta.unknown.com"),
				TrustChainsFilterMinPathLength,
			},
			in:       allChains,
			expected: nil,
		},
		{
			name: "all chains -> min unknown",
			filter: []TrustChainsFilter{
				TrustChainsFilterMinPathLength,
				TrustChainsFilterTrustAnchor("https://ta.unknown.com"),
			},
			in:       allChains,
			expected: nil,
		},
		{
			name: "ia1 chains -> ta1 min",
			filter: []TrustChainsFilter{
				TrustChainsFilterTrustAnchor(ta1.EntityID),
				TrustChainsFilterMinPathLength,
			},
			in: ia1Chains,
			expected: TrustChains{
				chainRPIA1TA1,
			},
		},
		{
			name: "ia1 chains -> ta2 min",
			filter: []TrustChainsFilter{
				TrustChainsFilterTrustAnchor(ta2.EntityID),
				TrustChainsFilterMinPathLength,
			},
			in: ia1Chains,
			expected: TrustChains{
				chainRPIA1IA2TA2,
			},
		},
		{
			name: "ia1 chains -> min ta2",
			filter: []TrustChainsFilter{
				TrustChainsFilterMinPathLength,
				TrustChainsFilterTrustAnchor(ta2.EntityID),
			},
			in:       ia1Chains,
			expected: nil,
		},
	}
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				filtered := test.in.Filter(test.filter...)
				if !compareTrustChains(filtered, test.expected) {
					t.Errorf(
						"filtered TrustChains are not what we expected:\n\nFiltered:\n%+v\n\nExpected:\n%+v\n\n",
						filtered, test.expected,
					)
				}
			},
		)
	}
}
