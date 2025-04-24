package pkg

import (
	"encoding/json"
	"slices"
	"strings"
	"time"

	arrays "github.com/adam-hanna/arrayOperations"
	"github.com/lithammer/fuzzysearch/fuzzy"
	"github.com/pkg/errors"
	"github.com/scylladb/go-set/strset"

	"github.com/zachmann/go-oidfed/internal"
	"github.com/zachmann/go-oidfed/internal/http"
	"github.com/zachmann/go-oidfed/internal/utils"
	"github.com/zachmann/go-oidfed/pkg/apimodel"
	"github.com/zachmann/go-oidfed/pkg/cache"
	"github.com/zachmann/go-oidfed/pkg/unixtime"
)

const defaultSubordinateListingCacheTime = time.Hour

// EntityCollectionResponse is a type describing the response of an entity
// collection request
type EntityCollectionResponse struct {
	FederationEntities []*CollectedEntity     `json:"federation_entities"`
	NextEntityID       string                 `json:"next_entity_id,omitempty"`
	LastUpdated        *unixtime.Unixtime     `json:"last_updated,omitempty"`
	Extra              map[string]interface{} `json:"-"`
}

// CollectedEntity is a type describing a single collected entity
type CollectedEntity struct {
	EntityID     string                 `json:"entity_id"`
	TrustMarks   TrustMarkInfos         `json:"trust_marks,omitempty"`
	TrustChain   JWSMessages            `json:"trust_chain,omitempty"`
	Metadata     *Metadata              `json:"metadata,omitempty"`
	EntityTypes  []string               `json:"entity_types,omitempty"`
	LogoURIs     map[string]string      `json:"logo_uris,omitempty"`
	DisplayNames map[string]string      `json:"display_names,omitempty"`
	Extra        map[string]interface{} `json:"-"`
}

// MarshalJSON implements the json.Marshaler interface
func (e CollectedEntity) MarshalJSON() ([]byte, error) {
	type Alias CollectedEntity
	explicitFields, err := json.Marshal(Alias(e))
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return extraMarshalHelper(explicitFields, e.Extra)
}

// UnmarshalJSON implements the json.Unmarshaler interface
func (e *CollectedEntity) UnmarshalJSON(data []byte) error {
	type Alias CollectedEntity
	ee := Alias(*e)

	extra, err := unmarshalWithExtra(data, &ee)
	if err != nil {
		return errors.WithStack(err)
	}
	ee.Extra = extra
	*e = CollectedEntity(ee)
	return nil
}

// EntityCollector is an interface that discovers / collects Entities in a
// federation
type EntityCollector interface {
	CollectEntities(req apimodel.EntityCollectionRequest) []*CollectedEntity
}

// SimpleEntityCollector is an EntityCollector that collects entities in a
// federation
type SimpleEntityCollector struct {
	visitedEntities *strset.Set
}

// SimpleOPCollector is an EntityCollector that uses the
// SimpleEntityCollector to collect OPs in a federation
type SimpleOPCollector struct{}

// CollectEntities implements the EntityCollector interface
func (d *SimpleOPCollector) CollectEntities(req apimodel.EntityCollectionRequest) (entities []*CollectedEntity) {
	req.EntityTypes = []string{"openid_provider"}
	return (&SimpleEntityCollector{}).CollectEntities(req)
}

// VerifiedChainsEntityCollector is an EntityCollector that compared to
// SimpleEntityCollector additionally verifies that there
// is a valid TrustChain between the entity and one of the specified trust
// anchors
type VerifiedChainsEntityCollector struct{}

// EntityCollectionFilter is an interface to filter discovered entities
type EntityCollectionFilter interface {
	Filter(*CollectedEntity) bool
}

type entityCollectionFilter struct {
	filter func(entity *CollectedEntity) bool
}

// Filter implements the EntityCollectionFilter interface
func (f entityCollectionFilter) Filter(entity *CollectedEntity) bool {
	return f.filter(entity)
}

// NewEntityCollectionFilter returns an EntityCollectionFilter for a filter func
func NewEntityCollectionFilter(filter func(entity *CollectedEntity) bool) EntityCollectionFilter {
	return entityCollectionFilter{filter: filter}
}

type filterableVerifiedChainsEntityCollector struct {
	Filters []EntityCollectionFilter
}

// FilterableVerifiedChainsEntityCollector is a type implementing
// EntityCollector
// that is able to filter the discovered OPs
// through a number of EntityCollectionFilter
type FilterableVerifiedChainsEntityCollector struct {
	Filters []EntityCollectionFilter
}

// CollectEntities implements the EntityCollector interface
func (d *SimpleEntityCollector) CollectEntities(req apimodel.EntityCollectionRequest) (entities []*CollectedEntity) {
	d.visitedEntities = strset.New()
	return d.collect(req, NewTrustAnchorsFromEntityIDs(req.TrustAnchor)...)
}

func (d *SimpleEntityCollector) collect(
	req apimodel.EntityCollectionRequest, authorities ...TrustAnchor,
) (entities []*CollectedEntity) {
	internal.Logf("Discovering Entities for authorities: %+q", authorities)
	var ta *EntityStatement
	infos := make(map[string]*CollectedEntity)
	for _, a := range authorities {
		if d.visitedEntities.Has(a.EntityID) {
			internal.Logf("Already visited: %s -> skipping", a.EntityID)
			continue
		}
		d.visitedEntities.Add(a.EntityID)
		internal.Logf("Discovering Entities for: %+q", a.EntityID)
		stmt, err := GetEntityConfiguration(a.EntityID)
		if err != nil {
			internal.Logf("Could not get entity configuration: %s -> skipping", err.Error())
			continue
		}
		if stmt.Metadata == nil || stmt.Metadata.FederationEntity == nil || stmt.Metadata.FederationEntity.FederationListEndpoint == "" {
			internal.Log("Could not get list endpoint from metadata -> skipping")
			continue
		}
		subordinates, err := fetchList(stmt.Metadata.FederationEntity.FederationListEndpoint)
		if err == nil {
			internal.Logf("Found these entities: %+q", subordinates)
			for _, s := range subordinates {
				internal.Logf("Checking subordinate: %+q", s)
				if _, alreadyProcessed := infos[s]; alreadyProcessed {
					internal.Log("Already processed -> skipping")
					continue
				}
				entityConfig, err := GetEntityConfiguration(s)
				if err != nil {
					internal.Logf("Could not get entity configuration: %s -> skipping", err.Error())
					continue
				}
				if entityConfig.Metadata == nil {
					internal.Log("No metadata present -> skipping")
					continue
				}
				et := entityConfig.Metadata.GuessEntityTypes()
				displayNames := entityConfig.Metadata.GuessDisplayNames()

				includeEntity := true
				if req.EntityTypes != nil && len(arrays.Intersect(et, req.EntityTypes)) == 0 {
					includeEntity = false
				}
				if req.NameQuery != "" && !matchDisplayName(req.NameQuery, displayNames, MatchModeFuzzy) {
					includeEntity = false
				}
				for _, trustMarkID := range req.TrustMarkIDs {
					trustMarkInfo := entityConfig.TrustMarks.FindByID(trustMarkID)
					if trustMarkInfo == nil {
						includeEntity = false
						break
					}
					if ta == nil {
						ta, err = GetEntityConfiguration(req.TrustAnchor)
						if err != nil {
							internal.Logf(
								"Could not get entity configuration for trust anchor: %s", err.Error(),
							)
							return
						}
					}
					if err = trustMarkInfo.VerifyFederation(&ta.EntityStatementPayload); err != nil {
						internal.Logf("trust mark '%s' did not verify: %s", trustMarkID, err.Error())
						includeEntity = false
						break
					}
				}

				if includeEntity {
					collectedEntity := &CollectedEntity{
						EntityID: s,
					}

					if req.Claims == nil || slices.Contains(req.Claims, "entity_types") {
						collectedEntity.EntityTypes = et
					}

					if req.Claims == nil || slices.Contains(req.Claims, "logo_uris") {
						collectedEntity.LogoURIs = entityConfig.Metadata.CollectStringClaim("logo_uri")
					}

					if req.Claims == nil || slices.Contains(req.Claims, "display_names") {
						collectedEntity.DisplayNames = displayNames
					}

					if slices.ContainsFunc(
						req.Claims, func(s string) bool { return s == "metadata" || s == "trust_chain" },
					) {
						resolveRequest := apimodel.ResolveRequest{
							Subject:     s,
							TrustAnchor: []string{req.TrustAnchor},
						}
						var res ResolveResponsePayload
						switch resolver := DefaultMetadataResolver.(type) {
						case LocalMetadataResolver:
							res, _, err = resolver.resolveResponsePayloadWithoutTrustMarks(resolveRequest)
						default:
							res, err = DefaultMetadataResolver.ResolveResponsePayload(resolveRequest)
						}
						if err != nil {
							internal.Logf("error while resolving trust chain for '%s': %s", s, err.Error())
						} else {
							if res.TrustMarks != nil && slices.Contains(req.Claims, "trust_marks") {
								collectedEntity.TrustMarks = res.TrustMarks
							}
							if slices.Contains(req.Claims, "metadata") {
								collectedEntity.Metadata = res.Metadata
							}
							if slices.Contains(req.Claims, "trust_chain") {
								collectedEntity.TrustChain = res.TrustChain
							}
						}
					}

					if collectedEntity.TrustMarks == nil && slices.Contains(req.Claims, "trust_marks") {
						if ta == nil {
							ta, err = GetEntityConfiguration(req.TrustAnchor)
							if err != nil {
								internal.Logf(
									"Could not get entity configuration for trust anchor: %s", err.Error(),
								)
								return
							}
						}
						collectedEntity.TrustMarks = entityConfig.TrustMarks.VerifiedFederation(&ta.EntityStatementPayload)
					}

					infos[s] = collectedEntity
					internal.Logf("Added Entity %+q", s)
				}

				if entityConfig.Metadata.FederationEntity != nil && entityConfig.Metadata.FederationEntity.FederationListEndpoint != "" {
					collectedEntitites := d.collect(req, NewTrustAnchorsFromEntityIDs(s)...)
					for _, e := range collectedEntitites {
						_, alreadyInList := infos[e.EntityID]
						if !alreadyInList {
							infos[e.EntityID] = e
						}
					}
				}
			}
		}
	}
	for _, e := range infos {
		entities = append(entities, e)
	}
	return
}

type matchMode string

const (
	MatchModeSubstringCaseInsensitive matchMode = "substring-case-insensitive"
	MatchModeSubstringCaseSensitive   matchMode = "substring-case-sensitive"
	MatchModeExactCaseSensitive       matchMode = "exact-case-sensitive"
	MatchModeExactCaseInsensitive     matchMode = "exact-case-insensitive"
	MatchModeFuzzy                    matchMode = "fuzzy"
)

func matchDisplayName(input string, names map[string]string, mode matchMode) bool {
	collectedNames := make([]string, len(names))
	i := 0
	for _, name := range names {
		collectedNames[i] = name
		i++
	}
	return matchWithMode(input, collectedNames, mode)
}

func matchWithMode(input string, names []string, mode matchMode) bool {
	switch mode {
	case MatchModeFuzzy:
		return len(fuzzy.FindNormalizedFold(input, names)) > 0
	case MatchModeExactCaseSensitive:
		return slices.Contains(names, input)
	case MatchModeExactCaseInsensitive:
		return slices.ContainsFunc(
			names, func(s string) bool {
				return strings.EqualFold(s, input)
			},
		)
	case MatchModeSubstringCaseSensitive:
		return slices.ContainsFunc(
			names, func(s string) bool {
				return strings.Contains(s, input)
			},
		)
	case MatchModeSubstringCaseInsensitive:
		return slices.ContainsFunc(
			names, func(s string) bool {
				return strings.Contains(strings.ToLower(s), strings.ToLower(input))
			},
		)
	default:
		return false
	}
}

// CollectEntities implements the EntityCollector interface
func (VerifiedChainsEntityCollector) CollectEntities(req apimodel.EntityCollectionRequest) (entities []*CollectedEntity) {
	return FilterableVerifiedChainsEntityCollector{}.CollectEntities(req)
}

// CollectEntities implements the EntityCollector interface
func (d filterableVerifiedChainsEntityCollector) CollectEntities(req apimodel.EntityCollectionRequest) (entities []*CollectedEntity) {
	in := (&SimpleEntityCollector{}).CollectEntities(req)
	for _, e := range in {
		var approved bool
		for _, f := range d.Filters {
			if approved = f.Filter(e); !approved {
				break
			}
		}
		if approved {
			entities = append(entities, e)
		}
	}
	return
}

// CollectEntities implements the EntityCollector interface
func (d FilterableVerifiedChainsEntityCollector) CollectEntities(req apimodel.EntityCollectionRequest) (entities []*CollectedEntity) {
	discoverer := filterableVerifiedChainsEntityCollector{
		Filters: append(
			[]EntityCollectionFilter{
				EntityCollectionFilterVerifiedChains{
					TrustAnchors: NewTrustAnchorsFromEntityIDs(req.TrustAnchor),
				},
			}, d.Filters...,
		),
	}
	return discoverer.CollectEntities(req)
}

// EntityCollectionFilterVerifiedChains is a EntityCollectionFilter that filters the discovered OPs to the one that have a
// valid TrustChain to one of the specified TrustAnchors
type EntityCollectionFilterVerifiedChains struct {
	TrustAnchors TrustAnchors
}

// Filter implements the EntityCollectionFilter interface
func (f EntityCollectionFilterVerifiedChains) Filter(e *CollectedEntity) bool {
	confirmedValid, _ := DefaultMetadataResolver.ResolvePossible(
		apimodel.ResolveRequest{
			Subject:     e.EntityID,
			TrustAnchor: f.TrustAnchors.EntityIDs(),
		},
	)
	return confirmedValid
}

func fetchList(listEndpoint string) ([]string, error) {
	if ids := subordinateListingCacheGet(listEndpoint); ids != nil {
		internal.Log("Obtained listing response from cache")
		return ids, nil
	}
	ids, err := httpFetchList(listEndpoint)
	if err != nil {
		return nil, err
	}
	internal.Log("Obtained listing response from http")
	subordinateListingCacheSet(listEndpoint, ids)
	return ids, nil
}

func httpFetchList(listEndpoint string) ([]string, error) {
	resp, errRes, err := http.Get(listEndpoint, nil, &[]string{})
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

func getMetadataForCollectedEntity(e *CollectedEntity, trustAnchors []string) *Metadata {
	if e.Metadata != nil {
		return e.Metadata
	}
	metadata, _ := DefaultMetadataResolver.Resolve(
		apimodel.ResolveRequest{
			Subject:     e.EntityID,
			TrustAnchor: trustAnchors,
		},
	)
	return metadata
}

// EntityCollectionFilterOPSupportedGrantTypesIncludes returns an
// EntityCollectionFilter that filters to OPs that support the
// passed grant types
func EntityCollectionFilterOPSupportedGrantTypesIncludes(
	trustAnchorIDs []string, neededGrantTypes ...string,
) EntityCollectionFilter {
	return NewEntityCollectionFilter(
		func(e *CollectedEntity) bool {
			if e == nil {
				return false
			}
			metadata := getMetadataForCollectedEntity(e, trustAnchorIDs)
			if metadata == nil || metadata.OpenIDProvider == nil {
				return false
			}
			return utils.ReflectIsSubsetOf(neededGrantTypes, metadata.OpenIDProvider.GrantTypesSupported)
		},
	)
}

// EntityCollectionFilterOPSupportedScopesIncludes returns an
// EntityCollectionFilter that filters to OPs that support the passed
// scopes
func EntityCollectionFilterOPSupportedScopesIncludes(
	trustAnchorIDs []string,
	neededScopes ...string,
) EntityCollectionFilter {
	return NewEntityCollectionFilter(
		func(e *CollectedEntity) bool {
			if e == nil {
				return false
			}
			metadata := getMetadataForCollectedEntity(e, trustAnchorIDs)
			if metadata == nil || metadata.OpenIDProvider == nil {
				return false
			}
			return utils.ReflectIsSubsetOf(neededScopes, metadata.OpenIDProvider.ScopesSupported)
		},
	)
}

// EntityCollectionFilterOPSupportsExplicitRegistration returns an
// EntityCollectionFilter that filters to OPs that support explicit registration
func EntityCollectionFilterOPSupportsExplicitRegistration(
	trustAnchorIDs []string,
) EntityCollectionFilter {
	return NewEntityCollectionFilter(
		func(e *CollectedEntity) bool {
			if e == nil {
				return false
			}
			metadata := getMetadataForCollectedEntity(e, trustAnchorIDs)
			if metadata == nil || metadata.OpenIDProvider == nil {
				return false
			}
			return slices.Contains(
				metadata.OpenIDProvider.ClientRegistrationTypesSupported, ClientRegistrationTypeExplicit,
			)
		},
	)
}

// EntityCollectionFilterOPSupportsAutomaticRegistration returns an
// EntityCollectionFilter that filters to OPs that support automatic
// registration
func EntityCollectionFilterOPSupportsAutomaticRegistration(
	trustAnchorIDs []string,
) EntityCollectionFilter {
	return NewEntityCollectionFilter(
		func(e *CollectedEntity) bool {
			if e == nil {
				return false
			}
			metadata := getMetadataForCollectedEntity(e, trustAnchorIDs)
			if metadata == nil || metadata.OpenIDProvider == nil {
				return false
			}
			return slices.Contains(
				metadata.OpenIDProvider.ClientRegistrationTypesSupported, ClientRegistrationTypeAutomatic,
			)
		},
	)
}

// EntityCollectionFilterOPs returns an EntityCollectionFilter that filters to OPs
func EntityCollectionFilterOPs(
	trustAnchorIDs []string,
) EntityCollectionFilter {
	return NewEntityCollectionFilter(
		func(e *CollectedEntity) bool {
			if e == nil {
				return false
			}
			return slices.Contains(e.EntityTypes, "openid_provider")
		},
	)
}

func subordinateListingCacheSet(listingEndpoint string, ids []string) {
	if err := cache.Set(
		cache.Key(cache.KeySubordinateListing, listingEndpoint), ids,
		defaultSubordinateListingCacheTime,
	); err != nil {
		internal.Log(err)
	}
}

func subordinateListingCacheGet(listingEndpoint string) []string {
	var ids []string
	set, err := cache.Get(cache.Key(cache.KeySubordinateListing, listingEndpoint), &ids)
	if err != nil {
		internal.Log(err)
		return nil
	}
	if !set {
		return nil
	}
	return ids
}
