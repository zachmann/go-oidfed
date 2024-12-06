package pkg

import (
	"net/url"

	"github.com/pkg/errors"

	"github.com/zachmann/go-oidfed/internal"
	"github.com/zachmann/go-oidfed/internal/http"
	"github.com/zachmann/go-oidfed/internal/utils"
	"github.com/zachmann/go-oidfed/pkg/apimodel"
)

// OPDiscoverer is an interface that discovers OPs
type OPDiscoverer interface {
	Discover(authorities ...string) []*OpenIDProviderMetadata
}

// SimpleOPDiscoverer is an OPDiscoverer that checks authorities for subordinate OPs and verifies that those
// publish openid_provider metadata in their EntityConfiguration
type SimpleOPDiscoverer struct{}

// VerifiedChainsOPDiscoverer is an OPDiscoverer that compared to VerifiedOPDiscoverer additionally verifies that there
// is a valid TrustChain between the op and one of the specified trust anchors
type VerifiedChainsOPDiscoverer struct{}

// OPDiscoveryFilter is an interface to filter discovered OPs
type OPDiscoveryFilter interface {
	Filter(*OpenIDProviderMetadata) bool
}

type opDiscoveryFilter struct {
	filter func(*OpenIDProviderMetadata) bool
}

// Filter implements the OPDiscoveryFilter interface
func (f opDiscoveryFilter) Filter(metadata *OpenIDProviderMetadata) bool {
	return f.filter(metadata)
}

// NewOPDiscoveryFilter returns an OPDiscoveryFilter a filter func
func NewOPDiscoveryFilter(filter func(metadata *OpenIDProviderMetadata) bool) OPDiscoveryFilter {
	return opDiscoveryFilter{filter: filter}
}

type filterableVerifiedChainsOPDiscoverer struct {
	Filters []OPDiscoveryFilter
}

// FilterableVerifiedChainsOPDiscoverer is a type implementing OPDiscoverer that is able to filter the discovered OPs
// through a number of OPDiscoveryFilter
type FilterableVerifiedChainsOPDiscoverer struct {
	Filters []OPDiscoveryFilter
}

// Discover implements the OPDiscoverer interface
func (d SimpleOPDiscoverer) Discover(authorities ...TrustAnchor) (opInfos []*OpenIDProviderMetadata) {
	internal.Logf("Discovering OPs for authorities: %+q", authorities)
	infos := make(map[string]*OpenIDProviderMetadata)
	for _, a := range authorities {
		internal.Logf("Discovering OPs and subordinates for: %+q", a.EntityID)
		stmt, err := GetEntityConfiguration(a.EntityID)
		if err != nil {
			internal.Logf("Could not get entity configuration: %s -> skipping", err.Error())
			continue
		}
		if stmt.Metadata == nil || stmt.Metadata.FederationEntity == nil || stmt.Metadata.FederationEntity.
			FederationListEndpoint == "" {
			internal.Log("Could not get list endpoint from metadata -> skipping")
			continue
		}
		thoseOPs, err := fetchList(stmt.Metadata.FederationEntity.FederationListEndpoint, "openid_provider")
		if err == nil {
			internal.Logf("Found these (possible) OPs: %+q", thoseOPs)
			for _, op := range thoseOPs {
				internal.Logf("Checking OP: %+q", op)
				if _, alreadyProcessed := infos[op]; alreadyProcessed {
					internal.Log("Already processed -> skipping")
					continue
				}
				entityConfig, err := GetEntityConfiguration(op)
				if err != nil {
					internal.Logf("Could not get entity configuration: %s -> skipping", err.Error())
					continue
				}
				if entityConfig.Metadata == nil || entityConfig.Metadata.OpenIDProvider == nil {
					internal.Log("No OP metadata present -> skipping")
					continue
				}
				opMetata := entityConfig.Metadata.OpenIDProvider
				if opMetata.OrganizationName == "" && entityConfig.Metadata.FederationEntity != nil && entityConfig.
					Metadata.FederationEntity.OrganizationName != "" {
					opMetata.OrganizationName = entityConfig.Metadata.FederationEntity.OrganizationName
				}
				infos[op] = opMetata
				internal.Logf("Added OP %+q", op)
			}
		}
		subordinates, err := fetchList(stmt.Metadata.FederationEntity.FederationListEndpoint, "federation_entity")
		if err != nil {
			continue
		}
		sOPs := d.Discover(NewTrustAnchorsFromEntityIDs(subordinates...)...)
		for _, sOP := range sOPs {
			_, alreadyInList := infos[sOP.Issuer]
			if alreadyInList {
				continue
			}
			infos[sOP.Issuer] = sOP
		}
	}
	for _, op := range infos {
		opInfos = append(opInfos, op)
	}
	return
}

// Discover implements the OPDiscoverer interface
func (VerifiedChainsOPDiscoverer) Discover(authorities ...TrustAnchor) (ops []*OpenIDProviderMetadata) {
	return FilterableVerifiedChainsOPDiscoverer{}.Discover(authorities...)
}

// Discover implements the OPDiscoverer interface
func (d filterableVerifiedChainsOPDiscoverer) Discover(authorities ...TrustAnchor) (opInfos []*OpenIDProviderMetadata) {
	in := SimpleOPDiscoverer{}.Discover(authorities...)
	for _, op := range in {
		var approved bool
		for _, f := range d.Filters {
			if approved = f.Filter(op); !approved {
				break
			}
		}
		if approved {
			opInfos = append(opInfos, op)
		}
	}
	return
}

// Discover implements the OPDiscoverer interface
func (d FilterableVerifiedChainsOPDiscoverer) Discover(authorities ...TrustAnchor) (opInfos []*OpenIDProviderMetadata) {
	discoverer := filterableVerifiedChainsOPDiscoverer{
		Filters: append(
			[]OPDiscoveryFilter{
				OPDiscoveryFilterVerifiedChains{
					TrustAnchors: authorities,
				},
			}, d.Filters...,
		),
	}
	return discoverer.Discover(authorities...)
}

// OPDiscoveryFilterVerifiedChains is a OPDiscoveryFilter that filters the discovered OPs to the one that have a
// valid TrustChain to one of the specified TrustAnchors
type OPDiscoveryFilterVerifiedChains struct {
	TrustAnchors TrustAnchors
}

// Filter implements the OPDiscoveryFilter interface
func (f OPDiscoveryFilterVerifiedChains) Filter(op *OpenIDProviderMetadata) bool {
	confirmedValid, _ := DefaultMetadataResolver.ResolvePossible(
		apimodel.ResolveRequest{
			Subject:     op.Issuer,
			TrustAnchor: f.TrustAnchors.EntityIDs(),
		},
	)
	return confirmedValid
}

type opDiscoveryFilterAutomaticRegistration struct{}

// Filter implements the OPDiscoveryFilter interface
func (opDiscoveryFilterAutomaticRegistration) Filter(op *OpenIDProviderMetadata) bool {
	return utils.SliceContains(ClientRegistrationTypeAutomatic, op.ClientRegistrationTypesSupported)
}

type opDiscoveryFilterExplicitRegistration struct{}

// Filter implements the OPDiscoveryFilter interface
func (opDiscoveryFilterExplicitRegistration) Filter(op *OpenIDProviderMetadata) bool {
	return utils.SliceContains(ClientRegistrationTypeExplicit, op.ClientRegistrationTypesSupported)
}

// OPDiscoveryFilterExplicitRegistration is an OPDiscoveryFilter that filters to OPs that support explicit registration
var OPDiscoveryFilterExplicitRegistration opDiscoveryFilterExplicitRegistration

// OPDiscoveryFilterAutomaticRegistration is an OPDiscoveryFilter that filters to OPs that support automatic registration
var OPDiscoveryFilterAutomaticRegistration opDiscoveryFilterAutomaticRegistration

func fetchList(listEndpoint, entityType string) ([]string, error) {
	params := url.Values{}
	params.Add("entity_type", entityType)
	resp, errRes, err := http.Get(listEndpoint, params, &[]string{})
	if err != nil {
		return nil, err
	}
	if errRes != nil {
		return nil, errRes.Err()
	}
	entities, ok := resp.Result().(*[]string)
	if !ok || entities == nil {
		return nil, errors.New("unexpected response type")
	}
	return *entities, nil
}

// OPDiscoveryFilterSupportedGrantTypesIncludes returns an OPDiscoveryFilter that filters to OPs that support the
// passed grant types
func OPDiscoveryFilterSupportedGrantTypesIncludes(neededGrantTypes ...string) OPDiscoveryFilter {
	return NewOPDiscoveryFilter(
		func(op *OpenIDProviderMetadata) bool {
			if op == nil {
				return false
			}
			return utils.ReflectIsSubsetOf(neededGrantTypes, op.GrantTypesSupported)
		},
	)
}

// OPDiscoveryFilterSupportedScopesIncludes returns an OPDiscoveryFilter that filters to OPs that support the passed
// scopes
func OPDiscoveryFilterSupportedScopesIncludes(neededScopes ...string) OPDiscoveryFilter {
	return NewOPDiscoveryFilter(
		func(op *OpenIDProviderMetadata) bool {
			if op == nil {
				return false
			}
			return utils.ReflectIsSubsetOf(neededScopes, op.ScopesSupported)
		},
	)
}
