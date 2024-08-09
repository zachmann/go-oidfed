package pkg

import (
	"encoding/json"
	"time"

	"github.com/pkg/errors"
)

var mockupData mockHttp

type mockHttp struct {
	entityConfigurations map[string][]byte
	entityListings       map[string]mockList
	entityStatements     map[string]mockFetch
}

type mockFetch map[string]map[string][]byte
type mockList []struct {
	EntityID   string
	EntityType string
}

func (d *mockHttp) addEntityConfiguration(entityid string, data []byte) {
	if d.entityConfigurations == nil {
		d.entityConfigurations = make(map[string][]byte)
	}
	d.entityConfigurations[entityid] = data
}
func (d *mockHttp) addEntityStatement(fetchEndpoint, iss, sub string, data []byte) {
	if d.entityStatements == nil {
		d.entityStatements = make(map[string]mockFetch)
	}
	if _, ok := d.entityStatements[fetchEndpoint]; !ok {
		d.entityStatements[fetchEndpoint] = make(mockFetch)
	}
	if _, ok := d.entityStatements[fetchEndpoint][iss]; !ok {
		d.entityStatements[fetchEndpoint][iss] = make(map[string][]byte)
	}
	d.entityStatements[fetchEndpoint][iss][sub] = data
}
func (d *mockHttp) addToListEndpoint(listEndpoint, entityID, entityType string) {
	if d.entityListings == nil {
		d.entityListings = make(map[string]mockList)
	}
	listing := d.entityListings[listEndpoint]
	for _, l := range listing {
		if l.EntityID == entityID {
			return
		}
	}
	listing = append(
		listing, struct {
			EntityID   string
			EntityType string
		}{
			EntityID:   entityID,
			EntityType: entityType,
		},
	)
	d.entityListings[listEndpoint] = listing
}

func (d mockHttp) GetEntityConfiguration(entityID string) ([]byte, error) {
	data, ok := d.entityConfigurations[entityID]
	if !ok {
		return nil, errors.New("entity configuration not found")
	}
	return data, nil
}
func (d mockHttp) FetchEntityStatement(fetchEndpoint, subID, issID string) ([]byte, error) {
	fetch, ok := d.entityStatements[fetchEndpoint]
	if !ok {
		return nil, errors.New("entity statement not found")
	}
	iss, ok := fetch[issID]
	if !ok {
		return nil, errors.New("entity statement not found")
	}
	data, ok := iss[subID]
	if !ok {
		return nil, errors.New("entity statement not found")
	}
	return data, nil
}

func (d mockHttp) ListEntities(listEndpoint, entityType string) ([]byte, error) {
	var entities []string
	listing := d.entityListings[listEndpoint]
	for _, l := range listing {
		if entityType == "" || l.EntityType == "" || entityType == l.EntityType {
			entities = append(entities, l.EntityID)
		}
	}
	return json.Marshal(entities)
}

func (d *mockHttp) AddRP(r mockRP) {
	data, err := r.JWT(r.EntityStatementPayload())
	if err != nil {
		panic(err)
	}
	d.addEntityConfiguration(r.EntityID, data)
}
func (d *mockHttp) AddOP(o mockOP) {
	data, err := o.JWT(o.EntityStatementPayload())
	if err != nil {
		panic(err)
	}
	d.addEntityConfiguration(o.EntityID, data)
}
func (d *mockHttp) AddProxy(p mockProxy) {
	data, err := p.JWT(p.EntityStatementPayload())
	if err != nil {
		panic(err)
	}
	d.addEntityConfiguration(p.EntityID, data)
}
func (d *mockHttp) AddTMI(tmi mockTMI) {
	now := time.Now()
	payload := EntityStatementPayload{
		Issuer:         tmi.EntityID,
		Subject:        tmi.EntityID,
		AuthorityHints: tmi.authorities,
		IssuedAt: Unixtime{
			Time: now,
		},
		ExpiresAt: Unixtime{
			Time: now.Add(defaultEntityConfigurationLifetime),
		},
		JWKS: tmi.jwks,
		Metadata: &Metadata{
			FederationEntity: &FederationEntityMetadata{
				FederationTrustMarkStatusEndpoint: "TODO", //TODO
				CommonMetadata: CommonMetadata{
					OrganizationName: "TMI Organization",
				},
			},
		},
	}
	data, err := tmi.TrustMarkSigner.JWT(payload)
	if err != nil {
		panic(err)
	}
	d.addEntityConfiguration(tmi.EntityID, data)
}

func (d *mockHttp) AddAuthority(a mockAuthority) {
	data, err := a.EntityStatementSigner.JWT(a.EntityStatementPayload())
	if err != nil {
		panic(err)
	}
	d.addEntityConfiguration(a.EntityID, data)

	for _, sub := range a.subordinates {
		pay := a.SubordinateEntityStatementPayload(sub.entityID)
		data, err = a.EntityStatementSigner.JWT(pay)
		if err != nil {
			panic(err)
		}
		d.addEntityStatement(a.FetchEndpoint, a.EntityID, sub.entityID, data)
		d.addToListEndpoint(a.ListEndpoint, sub.entityID, "")
	}
}
