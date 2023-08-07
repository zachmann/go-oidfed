package pkg

import (
	"encoding/json"

	"github.com/lestrrat-go/jwx/jws"
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
	ec := r.EntityConfiguration()
	data, err := ec.JWT()
	if err != nil {
		panic(err)
	}
	d.addEntityConfiguration(r.EntityID, data)
}
func (d *mockHttp) AddOP(o mockOP) {
	ec := o.EntityConfiguration()
	data, err := ec.JWT()
	if err != nil {
		panic(err)
	}
	d.addEntityConfiguration(o.EntityID, data)
}

func (d *mockHttp) AddAuthority(a mockAuthority) {
	ec := a.EntityConfiguration()
	data, err := ec.JWT()
	if err != nil {
		panic(err)
	}
	d.addEntityConfiguration(a.EntityID, data)

	for _, sub := range a.subordinates {
		pay := a.SubordinateEntityStatementPayload(sub.entityID)
		j, err := pay.MarshalJSON()
		if err != nil {
			panic(err)
		}
		headers := jws.NewHeaders()
		if err = headers.Set(jws.TypeKey, "entity-statement+jwt"); err != nil {
			panic(err)
		}
		data, err := jws.Sign(j, a.signingAlg, a.signer, jws.WithHeaders(headers))
		if err != nil {
			panic(err)
		}
		d.addEntityStatement(a.FetchEndpoint, a.EntityID, sub.entityID, data)
		d.addToListEndpoint(a.ListEndpoint, sub.entityID, "")
	}
}
