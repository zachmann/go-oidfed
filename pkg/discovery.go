package pkg

import (
	"encoding/json"

	arrayops "github.com/adam-hanna/arrayOperations"

	"github.com/zachmann/go-oidcfed/internal"
	"github.com/zachmann/go-oidcfed/internal/utils"
)

type OPDiscoverer interface {
	Discover(authorities ...string) []*OpenIDProviderMetadata
}

// SimpleOPDiscoverer is an OPDiscoverer that checks authorities for subordinate OPs and verifies that those
// publish openid_provider metadata in their EntityConfiguration
type SimpleOPDiscoverer struct{}

// VerifiedChainsOPDiscoverer is an OPDiscoverer that compared to VerifiedOPDiscoverer additionally verifies that there
// is a valid TrustChain between the op and one of the specified trust anchors
type VerifiedChainsOPDiscoverer struct{}

type OPDiscoveryFilter interface {
	Filter(*OpenIDProviderMetadata) bool
}

type opDiscoveryFilter struct {
	filter func(*OpenIDProviderMetadata) bool
}

func (f opDiscoveryFilter) Filter(metadata *OpenIDProviderMetadata) bool {
	return f.filter(metadata)
}

func NewOPDiscoveryFilter(filter func(metadata *OpenIDProviderMetadata) bool) OPDiscoveryFilter {
	return opDiscoveryFilter{filter: filter}
}

type filterableVerifiedChainsOPDiscoverer struct {
	Filters []OPDiscoveryFilter
}

type FilterableVerifiedChainsOPDiscoverer struct {
	Filters []OPDiscoveryFilter
}

func (d SimpleOPDiscoverer) Discover(authorities ...TrustAnchor) (opInfos []*OpenIDProviderMetadata) {
	internal.Logf("Discovering OPs for authorities: %+q", authorities)
	for _, a := range authorities {
		internal.Logf("Discovering OPs and subordinates for: %+q", a.EntityID)
		stmt, err := getEntityConfiguration(a.EntityID)
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
				entityConfig, err := getEntityConfiguration(op)
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
				internal.Logf("Added OP %+q", op)
				opInfos = append(opInfos, opMetata)
			}
		}
		subordinates, err := fetchList(stmt.Metadata.FederationEntity.FederationListEndpoint, "federation_entity")
		if err != nil {
			continue
		}
		sOPs := d.Discover(NewTrustAnchorsFromEntityIDs(subordinates...)...)
		opInfos = arrayops.Union(opInfos, sOPs)
	}
	return
}

func (VerifiedChainsOPDiscoverer) Discover(authorities ...TrustAnchor) (ops []*OpenIDProviderMetadata) {
	return FilterableVerifiedChainsOPDiscoverer{}.Discover(authorities...)
}

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

type OPDiscoveryFilterVerifiedChains struct {
	TrustAnchors TrustAnchors
}

func (f OPDiscoveryFilterVerifiedChains) Filter(op *OpenIDProviderMetadata) bool {
	resolver := TrustResolver{
		TrustAnchors:   f.TrustAnchors,
		StartingEntity: op.Issuer,
	}
	return len(resolver.ResolveToValidChains()) > 0
}

type opDiscoveryFilterAutomaticRegistration struct{}

func (opDiscoveryFilterAutomaticRegistration) Filter(op *OpenIDProviderMetadata) bool {
	return utils.SliceContains(ClientRegistrationTypeAutomatic, op.ClientRegistrationTypesSupported)
}

type opDiscoveryFilterExplicitRegistration struct{}

func (opDiscoveryFilterExplicitRegistration) Filter(op *OpenIDProviderMetadata) bool {
	return utils.SliceContains(ClientRegistrationTypeExplicit, op.ClientRegistrationTypesSupported)
}

var OPDiscoveryFilterExplicitRegistration opDiscoveryFilterExplicitRegistration
var OPDiscoveryFilterAutomaticRegistration opDiscoveryFilterAutomaticRegistration

func fetchList(listEndpoint, entityType string) ([]string, error) {
	body, err := entityStatementObtainer.ListEntities(listEndpoint, entityType)
	if err != nil {
		return nil, err
	}
	var entities []string
	if err = json.Unmarshal(body, &entities); err != nil {
		return nil, err
	}
	return entities, nil
}

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
