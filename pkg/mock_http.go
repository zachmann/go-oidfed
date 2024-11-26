package pkg

import (
	"encoding/json"
	"time"

	"github.com/pkg/errors"

	"github.com/zachmann/go-oidfed/pkg/unixtime"
)

var mockupData mockHttp

type mockHttp struct {
	entityConfigurations map[string]func() []byte
	entityListings       map[string]mockList
	entityStatements     map[string]func(iss, sub string) []byte
}
type mockList []struct {
	EntityID   string
	EntityType string
}

func (d *mockHttp) addEntityConfiguration(entityid string, fnc func() []byte) {
	if d.entityConfigurations == nil {
		d.entityConfigurations = make(map[string]func() []byte)
	}
	d.entityConfigurations[entityid] = fnc
}
func (d *mockHttp) addEntityStatement(fetchEndpoint string, fnc func(iss, sub string) []byte) {
	if d.entityStatements == nil {
		d.entityStatements = make(map[string]func(iss, sub string) []byte)
	}
	d.entityStatements[fetchEndpoint] = fnc
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
	fnc, ok := d.entityConfigurations[entityID]
	if !ok {
		return nil, errors.New("entity configuration not found")
	}
	return fnc(), nil
}
func (d mockHttp) FetchEntityStatement(fetchEndpoint, subID, issID string) ([]byte, error) {
	fetch, ok := d.entityStatements[fetchEndpoint]
	if !ok {
		return nil, errors.New("entity statement not found")
	}
	return fetch(issID, subID), nil
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
	d.addEntityConfiguration(
		r.EntityID, func() []byte {
			data, err := r.JWT(r.EntityStatementPayload())
			if err != nil {
				panic(err)
			}
			return data
		},
	)
}
func (d *mockHttp) AddOP(o mockOP) {
	d.addEntityConfiguration(
		o.EntityID, func() []byte {
			data, err := o.JWT(o.EntityStatementPayload())
			if err != nil {
				panic(err)
			}
			return data
		},
	)
}
func (d *mockHttp) AddProxy(p mockProxy) {
	d.addEntityConfiguration(
		p.EntityID, func() []byte {
			data, err := p.JWT(p.EntityStatementPayload())
			if err != nil {
				panic(err)
			}
			return data
		},
	)
}
func (d *mockHttp) AddTMI(tmi mockTMI) {
	d.addEntityConfiguration(
		tmi.EntityID, func() []byte {
			now := time.Now()
			payload := EntityStatementPayload{
				Issuer:         tmi.EntityID,
				Subject:        tmi.EntityID,
				AuthorityHints: tmi.authorities,
				IssuedAt: unixtime.Unixtime{
					Time: now,
				},
				ExpiresAt: unixtime.Unixtime{
					Time: now.Add(defaultEntityConfigurationLifetime),
				},
				JWKS: tmi.jwks,
				Metadata: &Metadata{
					FederationEntity: &FederationEntityMetadata{
						FederationTrustMarkStatusEndpoint: "TODO", //TODO
						OrganizationName:                  "TMI Organization",
					},
				},
			}
			data, err := tmi.TrustMarkSigner.JWT(payload)
			if err != nil {
				panic(err)
			}
			return data
		},
	)
}

func (d *mockHttp) AddAuthority(a mockAuthority) {
	d.addEntityConfiguration(
		a.EntityID, func() []byte {
			data, err := a.EntityStatementSigner.JWT(a.EntityStatementPayload())
			if err != nil {
				panic(err)
			}
			return data
		},
	)
	d.addEntityStatement(
		a.FetchEndpoint, func(iss, sub string) []byte {
			pay := a.SubordinateEntityStatementPayload(sub)
			data, err := a.EntityStatementSigner.JWT(pay)
			if err != nil {
				panic(err)
			}
			return data
		},
	)
	for _, sub := range a.subordinates {
		d.addToListEndpoint(a.ListEndpoint, sub.entityID, "")
	}
}
