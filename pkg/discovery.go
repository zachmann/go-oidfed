package pkg

import (
	"encoding/json"

	arrayops "github.com/adam-hanna/arrayOperations"

	"github.com/zachmann/go-oidcfed/internal/cache"
)

type OPDiscoverer interface {
	Discover(authorities ...string) []string
}

// SimpleOPDiscoverer is a simple OPDiscoverer that just checks trust anchors and subordinates for openid providers
type SimpleOPDiscoverer struct{}

// VerifiedOPDiscoverer is an OPDiscoverer that compared to SimpleOPDiscoverer additionally verifies that the
// entities publish openid_provider metadata in their EntityConfiguration
type VerifiedOPDiscoverer struct {
	simple SimpleOPDiscoverer
}

// VerifiedChainsOPDiscoverer is an OPDiscoverer that compared to VerifiedOPDiscoverer additionally verifies that there
// is a valid TrustChain between the op and one of the specified trust anchors
type VerifiedChainsOPDiscoverer struct {
	verified VerifiedOPDiscoverer
}

func (d SimpleOPDiscoverer) Discover(authorities ...string) (ops []string) {
	for _, a := range authorities {
		stmt, err := getEntityConfiguration(a)
		if err != nil {
			continue
		}
		if stmt.Metadata == nil || stmt.Metadata.FederationEntity == nil || stmt.Metadata.FederationEntity.
			FederationListEndpoint == "" {
			continue
		}
		thoseOPs, err := fetchList(stmt.Metadata.FederationEntity.FederationListEndpoint, "openid_provider")
		if err == nil {
			ops = arrayops.Union(ops, thoseOPs)
		}
		subordinates, err := fetchList(stmt.Metadata.FederationEntity.FederationListEndpoint, "federation_entity")
		if err != nil {
			continue
		}
		sOPs := d.Discover(subordinates...)
		ops = arrayops.Union(ops, sOPs)
	}
	return
}

func (d VerifiedOPDiscoverer) Discover(authorities ...string) (ops []string) {
	simpleOPs := d.simple.Discover(authorities...)
	for _, op := range simpleOPs {
		entityConfig, err := getEntityConfiguration(op)
		if err != nil {
			continue
		}
		if entityConfig.Metadata == nil || entityConfig.Metadata.OpenIDProvider == nil {
			continue
		}
		ops = append(ops, op)
	}
	return
}

func (d VerifiedChainsOPDiscoverer) Discover(authorities ...string) (ops []string) {
	verifiedOPs := d.verified.Discover(authorities...)
	for _, op := range verifiedOPs {
		resolver := TrustResolver{
			TrustAnchors:   authorities,
			StartingEntity: op,
		}
		if len(resolver.ResolveToValidChains()) > 0 {
			ops = append(ops, op)
		}
	}
	return
}

func listEndpointCacheSet(endpoint, entityType string, entities []string) {
	cache.Set(
		cache.ListingCacheKey(endpoint, entityType), entities, 0,
	)
}
func listEndpointCacheGet(endpoint, entityType string) []string {
	e, ok := cache.Get(cache.ListingCacheKey(endpoint, entityType))
	if !ok {
		return nil
	}
	entities, ok := e.([]string)
	if !ok {
		return nil
	}
	return entities
}

func fetchList(listEndpoint, entityType string) ([]string, error) {
	if entities := listEndpointCacheGet(listEndpoint, entityType); entities != nil {
		return entities, nil
	}
	body, err := entityStatementObtainer.ListEntities(listEndpoint, entityType)
	if err != nil {
		return nil, err
	}
	var entities []string
	if err = json.Unmarshal(body, &entities); err != nil {
		return nil, err
	}
	listEndpointCacheSet(listEndpoint, entityType, entities)
	return entities, nil
}
