package pkg

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"unsafe"
)

// Metadata is a type for holding the different metadata types
type Metadata struct {
	OpenIDProvider           *OpenIDProviderMetadata           `json:"openid_provider,omitempty"`
	RelyingParty             *OpenIDRelyingPartyMetadata       `json:"openid_relying_party,omitempty"`
	OAuthAuthorizationServer *OAuthAuthorizationServerMetadata `json:"oauth_authorization_server,omitempty"`
	OAuthClient              *OAuthClientMetadata              `json:"oauth_client,omitempty"`
	OAuthProtectedResource   *OAuthProtectedResourceMetadata   `json:"oauth_resource,omitempty"`
	FederationEntity         *FederationEntityMetadata         `json:"federation_entity,omitempty"`
}

// GuessEntityTypes returns a slice of entity types for which metadata is set
func (m Metadata) GuessEntityTypes() (entityTypes []string) {
	value := reflect.ValueOf(m)
	typ := value.Type()
	for i := 0; i < value.NumField(); i++ {
		field := value.Field(i)
		if field.Kind() == reflect.Ptr && !field.IsNil() {
			structField := typ.Field(i)
			jsonTag := structField.Tag.Get("json")
			jsonTag = strings.TrimSuffix(jsonTag, ",omitempty")
			entityTypes = append(entityTypes, jsonTag)
		}
	}
	return
}

type policyApplicable interface {
	ApplyPolicy(policy MetadataPolicy) (any, error)
}

// ApplyPolicy applies MetadataPolicies to Metadata and returns the final Metadata
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

	wasSetField := v.Elem().FieldByName("wasSet")
	wasSet := *(*map[string]bool)(unsafe.Pointer(wasSetField.UnsafeAddr()))
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
		value, err := p.ApplyTo(f.Interface(), wasSet[t.Field(i).Name], fmt.Sprintf("%s.%s", ownTag, j))
		if err != nil {
			return nil, err
		}
		rV := reflect.ValueOf(value)
		if rV.IsValid() {
			f.Set(rV)
		} else {
			f.SetZero()
		}
	}

	return metadata, nil
}

// OAuthClientMetadata is a type for holding the metadata about an oauth client
type OAuthClientMetadata OpenIDRelyingPartyMetadata
type oAuthClientMetadataWithPtrs openIDRelyingPartyMetadataWithPtrs

// OAuthAuthorizationServerMetadata is a type for holding the metadata about an oauth authorization server
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

type oAuthAuthorizationServerMetadataWithPtrs openIDProviderMetadataWithPtrs

// MarshalJSON implements the json.Marshaler interface
func (m oAuthAuthorizationServerMetadataWithPtrs) MarshalJSON() ([]byte, error) {
	return json.Marshal(openIDProviderMetadataWithPtrs(m))
}

// UnmarshalJSON implements the json.Unmarshaler interface
func (m *oAuthAuthorizationServerMetadataWithPtrs) UnmarshalJSON(data []byte) error {
	op := openIDProviderMetadataWithPtrs(*m)
	if err := json.Unmarshal(data, &op); err != nil {
		return err
	}
	*m = oAuthAuthorizationServerMetadataWithPtrs(op)
	return nil
}

// ApplyPolicy applies a MetadataPolicy to the OAuthAuthorizationServerMetadata
func (m OAuthAuthorizationServerMetadata) ApplyPolicy(policy MetadataPolicy) (any, error) {
	return applyPolicy(&m, policy, "oauth_authorization_server")
}

// MarshalJSON implements the json.Marshaler interface
func (m OAuthClientMetadata) MarshalJSON() ([]byte, error) {
	return json.Marshal(OpenIDRelyingPartyMetadata(m))
}

// UnmarshalJSON implements the json.Unmarshaler interface
func (m *OAuthClientMetadata) UnmarshalJSON(data []byte) error {
	rp := OpenIDRelyingPartyMetadata(*m)
	if err := json.Unmarshal(data, &rp); err != nil {
		return err
	}
	*m = OAuthClientMetadata(rp)
	return nil
}

// MarshalJSON implements the json.Marshaler interface
func (m oAuthClientMetadataWithPtrs) MarshalJSON() ([]byte, error) {
	return json.Marshal(openIDRelyingPartyMetadataWithPtrs(m))
}

// UnmarshalJSON implements the json.Unmarshaler interface
func (m *oAuthClientMetadataWithPtrs) UnmarshalJSON(data []byte) error {
	rp := openIDRelyingPartyMetadataWithPtrs(*m)
	if err := json.Unmarshal(data, &rp); err != nil {
		return err
	}
	*m = oAuthClientMetadataWithPtrs(rp)
	return nil
}

// ApplyPolicy applies a MetadataPolicy to the OAuthClientMetadata
func (m OAuthClientMetadata) ApplyPolicy(policy MetadataPolicy) (any, error) {
	return applyPolicy(&m, policy, "oauth_client")
}
