package pkg

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

type Metadata struct {
	OpenIDProvider           *OpenIDProviderMetadata           `json:"openid_provider,omitempty"`
	RelyingParty             *OpenIDRelyingPartyMetadata       `json:"openid_relying_party,omitempty"`
	OAuthAuthorizationServer *OAuthAuthorizationServerMetadata `json:"oauth_authorization_server,omitempty"`
	OAuthClient              *OAuthClientMetadata              `json:"oauth_client,omitempty"`
	OAuthProtectedResource   *OAuthProtectedResourceMetadata   `json:"oauth_resource,omitempty"`
	FederationEntity         *FederationEntityMetadata         `json:"federation_entity,omitempty"`
}

type policyApplicable interface {
	ApplyPolicy(policy MetadataPolicy) (any, error)
}

func (m Metadata) ApplyPolicy(p *MetadataPolicies) (*Metadata, error) {
	if p == nil {
		return &m, nil
	}
	t := reflect.TypeOf(m)
	v := reflect.ValueOf(m)
	out := &Metadata{}
	for i := 0; i < t.NumField(); i++ {
		policy, policyOk := reflect.ValueOf(*p).Field(i).Interface().(MetadataPolicy)
		if !policyOk || policy == nil {
			reflect.Indirect(reflect.ValueOf(out)).Field(i).Set(v.Field(i))
			continue
		}
		var metadata policyApplicable
		f := v.Field(i)
		if f.IsNil() {
			continue
		}
		var ok bool
		metadata, ok = v.Field(i).Interface().(policyApplicable)
		if !ok {
			continue
		}
		applied, err := metadata.ApplyPolicy(policy)
		if err != nil {
			return nil, err
		}
		reflect.Indirect(reflect.ValueOf(out)).Field(i).Set(reflect.ValueOf(applied))
	}
	return out, nil
}

type metadatas interface {
	*OpenIDProviderMetadata | *OpenIDRelyingPartyMetadata | *OAuthAuthorizationServerMetadata | *OAuthClientMetadata | *OAuthProtectedResourceMetadata | *FederationEntityMetadata
}

func applyPolicy[M metadatas](metadata M, policy MetadataPolicy, ownTag string) (any, error) {
	if policy == nil {
		return metadata, nil
	}
	v := reflect.ValueOf(metadata)
	t := v.Elem().Type()
	for i := 0; i < t.NumField(); i++ {
		j, ok := t.Field(i).Tag.Lookup("json")
		if !ok {
			continue
		}
		j = strings.TrimSuffix(j, ",omitempty")
		p, ok := policy[j]
		if !ok {
			continue
		}
		f := reflect.Indirect(v).Field(i)
		value, err := p.ApplyTo(f.Interface(), fmt.Sprintf("%s.%s", ownTag, j))
		if err != nil {
			return nil, err
		}
		rV := reflect.ValueOf(value)
		if rV.IsValid() {
			f.Set(rV)
		}
	}

	return metadata, nil
}

type OAuthClientMetadata OpenIDRelyingPartyMetadata
type OAuthAuthorizationServerMetadata OpenIDProviderMetadata

// MarshalJSON implements the json.Marshaler interface
func (m OAuthAuthorizationServerMetadata) MarshalJSON() ([]byte, error) {
	return json.Marshal(OpenIDProviderMetadata(m))
}

// UnmarshalJSON implements the json.Unmarshaler interface
func (m *OAuthAuthorizationServerMetadata) UnmarshalJSON(data []byte) error {
	op := OpenIDProviderMetadata(*m)
	if err := json.Unmarshal(data, &op); err != nil {
		return err
	}
	*m = OAuthAuthorizationServerMetadata(op)
	return nil
}
func (m OAuthAuthorizationServerMetadata) ApplyPolicy(policy MetadataPolicy) (any, error) {
	return applyPolicy(&m, policy, "oauth_authorization_server")
}

func (m OAuthClientMetadata) MarshalJSON() ([]byte, error) {
	return json.Marshal(OpenIDRelyingPartyMetadata(m))
}
func (m *OAuthClientMetadata) UnmarshalJSON(data []byte) error {
	rp := OpenIDRelyingPartyMetadata(*m)
	if err := json.Unmarshal(data, &rp); err != nil {
		return err
	}
	*m = OAuthClientMetadata(rp)
	return nil
}
func (m OAuthClientMetadata) ApplyPolicy(policy MetadataPolicy) (any, error) {
	return applyPolicy(&m, policy, "oauth_client")
}
