package pkg

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/luci/go-render/render"
)

type marshalData struct {
	Data   []byte
	Object any
}

var entitystatementMarshalData = map[string]marshalData{
	"empty": {
		Data:   []byte(`{"exp":0,"iat":0,"iss":"","jwks":null,"sub":""}`),
		Object: EntityStatementPayload{},
	},
	"normal fields": {
		Data: []byte(`{"aud":"aud","authority_hints":["hint1","hint2"],"constraints":{"max_path_length":2,"naming_constraints":{"permitted":["foo"]},"allowed_entity_types":["openid_provider"]},"crit":["jti"],"exp":200,"iat":100,"iss":"issuer","jwks":null,"metadata":{"openid_relying_party":{"application_type":"web","client_registration_types":["automatic"],"contacts":["contact@email.com"],"grant_types":["refresh_token","authorization_code"],"id_token_signed_response_alg":"ES512","redirect_uris":["https://redirect.to.somewher"],"response_types":["code"],"scope":"some scope"},"federation_entity":{"homepage_uri":"https://somewhere.com","organization_name":"organization"}},"metadata_policy":{"federation_entity":{"contacts":{"add":"value"}}},"metadata_policy_crit":["remove"],"sub":"subject"}`),
		Object: EntityStatementPayload{
			Issuer:    "issuer",
			Subject:   "subject",
			IssuedAt:  Unixtime{time.Unix(100, 0)},
			ExpiresAt: Unixtime{time.Unix(200, 0)},
			Audience:  "aud",
			AuthorityHints: []string{
				"hint1",
				"hint2",
			},
			Metadata: &Metadata{
				RelyingParty: &OpenIDRelyingPartyMetadata{
					Scope:         "some scope",
					RedirectURIS:  []string{"https://redirect.to.somewher"},
					ResponseTypes: []string{"code"},
					GrantTypes: []string{
						"refresh_token",
						"authorization_code",
					},
					ApplicationType:          "web",
					Contacts:                 []string{"contact@email.com"},
					IDTokenSignedResponseAlg: "ES512",
					ClientRegistrationTypes:  []string{"automatic"},
				},
				FederationEntity: &FederationEntityMetadata{
					OrganizationName: "organization",
					HomepageURI:      "https://somewhere.com",
				},
			},
			MetadataPolicy: &MetadataPolicies{
				FederationEntity: MetadataPolicy{
					"contacts": {
						"add": "value",
					},
				},
			},
			Constraints: &ConstraintSpecification{
				MaxPathLength: 2,
				NamingConstraints: NamingConstraints{
					Permitted: []string{"foo"},
				},
				AllowedLeafEntityTypes: []string{"openid_provider"},
			},
			CriticalExtensions: []string{"jti"},
			MetadataPolicyCrit: []PolicyOperatorName{"remove"},
			Extra:              nil,
		},
	},
	"extra fields": {
		Data: []byte(`{"exp":200,"extra-field":"value","foo":["bar"],"iat":100,"iss":"issuer","jwks":null,"sub":"subject"}`),
		Object: EntityStatementPayload{
			IssuedAt:  Unixtime{time.Unix(100, 0)},
			ExpiresAt: Unixtime{time.Unix(200, 0)},
			Issuer:    "issuer",
			Subject:   "subject",
			Extra: map[string]interface{}{
				"extra-field": "value",
				"foo":         []any{"bar"},
			},
		},
	},
}

func TestEntityStatementPayload_MarshalJSON(t *testing.T) {
	tests := []struct {
		name string
		marshalData
	}{
		{
			name:        "all normal fields",
			marshalData: entitystatementMarshalData["normal fields"],
		},
		{
			name:        "extra",
			marshalData: entitystatementMarshalData["extra fields"],
		},
	}
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				j, err := json.Marshal(test.Object)
				if err != nil {
					t.Error(err)
				}
				if !bytes.Equal(j, test.Data) {
					t.Errorf("Marshal result not as expected.\nExpected: %s\n     Got: %s", test.Data, j)
				}
			},
		)
	}
}

func TestEntityStatementPayload_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name string
		marshalData
	}{
		{
			name:        "all normal fields",
			marshalData: entitystatementMarshalData["normal fields"],
		},
		{
			name:        "extra",
			marshalData: entitystatementMarshalData["extra fields"],
		},
	}
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				var result EntityStatementPayload
				err := json.Unmarshal(test.Data, &result)
				if err != nil {
					t.Error(err)
				}
				if !reflect.DeepEqual(test.Object, result) {
					t.Errorf(
						"Unmarshal result not as expected.\nExpected: %s\n     Got: %s", render.Render(test.Object),
						render.Render(result),
					)
				}
			},
		)
	}
}
