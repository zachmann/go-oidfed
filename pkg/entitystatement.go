package pkg

import (
	"crypto"
	"encoding/json"
	"math"
	"time"

	"github.com/zachmann/go-oidfed/internal/jwx"
	"github.com/zachmann/go-oidfed/internal/utils"

	"github.com/fatih/structs"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/pkg/errors"
)

const defaultEntityConfigurationLifetime = 86400 // 1d

// EntityStatement is a type for holding an entity statement, more precisely an entity statement that was obtained
// as a jwt and created by us
type EntityStatement struct {
	jwtMsg *jws.Message
	EntityStatementPayload
}

// Verify verifies that the EntityStatement jwt is valid
func (e EntityStatement) Verify(keys jwk.Set) bool {
	_, err := jwx.VerifyWithSet(e.jwtMsg, keys)
	return err == nil
}

// EntityConfiguration is a type for holding an entity configuration, more precisely an entity statement from an entity
// about itself that was created by us. To create a new EntityConfiguration use the NewEntityConfiguration function
type EntityConfiguration struct {
	EntityStatementPayload
	key crypto.Signer
	jwt []byte
	alg jwa.SignatureAlgorithm
}

// JWT returns a signed jwt representation of the EntityConfiguration
func (e *EntityConfiguration) JWT() (jwt []byte, err error) {
	if e.jwt != nil {
		jwt = e.jwt
		return
	}
	if e.key == nil {
		return nil, errors.New("no signing key set")
	}
	var j []byte
	j, err = json.Marshal(e)
	if err != nil {
		return
	}
	e.jwt, err = jwx.SignEntityStatement(j, e.alg, e.key)
	jwt = e.jwt
	return
}

// NewEntityConfiguration creates a new EntityConfiguration with the passed EntityStatementPayload and the passed
// signing key and jwa.SignatureAlgorithm
func NewEntityConfiguration(
	payload EntityStatementPayload, privateSigningKey crypto.Signer,
	signingAlg jwa.SignatureAlgorithm,
) *EntityConfiguration {
	return &EntityConfiguration{
		EntityStatementPayload: payload,
		key:                    privateSigningKey,
		alg:                    signingAlg,
	}
}

// EntityStatementPayload is a type for holding the actual payload of an EntityStatement or EntityConfiguration;
// additional fields can be set in the Extra claim
type EntityStatementPayload struct {
	Issuer             string                   `json:"iss"`
	Subject            string                   `json:"sub"`
	IssuedAt           Unixtime                 `json:"iat"`
	ExpiresAt          Unixtime                 `json:"exp"`
	JWKS               jwk.Set                  `json:"jwks"`
	Audience           string                   `json:"aud,omitempty"`
	AuthorityHints     []string                 `json:"authority_hints,omitempty"`
	Metadata           *Metadata                `json:"metadata,omitempty"`
	MetadataPolicy     *MetadataPolicies        `json:"metadata_policy,omitempty"`
	Constraints        *ConstraintSpecification `json:"constraints,omitempty"`
	CriticalExtensions []string                 `json:"crit,omitempty"`
	MetadataPolicyCrit []PolicyOperatorName     `json:"metadata_policy_crit,omitempty"`
	TrustMarks         []TrustMark              `json:"trust_marks,omitempty"`
	TrustMarkIssuers   AllowedTrustMarkIssuers  `json:"trust_mark_issuers,omitempty"`
	TrustMarkOwners    TrustMarkOwners          `json:"trust_mark_owners,omitempty"`
	SourceEndpoint     string                   `json:"source_endpoint,omitempty"`
	TrustAnchorID      string                   `json:"trust_anchor_id,omitempty"`
	Extra              map[string]interface{}   `json:"-"`
}

// TimeValid checks if the EntityStatementPayload is already valid and not yet expired.
func (e EntityStatementPayload) TimeValid() bool {
	return verifyTime(e.IssuedAt, e.ExpiresAt) == nil
}

func extraMarshalHelper(explicitFields []byte, extra map[string]interface{}) ([]byte, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(explicitFields, &m); err != nil {
		return nil, err
	}
	for k, v := range extra {
		e, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		m[k] = e
	}
	return json.Marshal(m)
}

// MarshalJSON implements the json.Marshaler interface.
// It also marshals extra fields.
func (e EntityStatementPayload) MarshalJSON() ([]byte, error) {
	type entityStatement EntityStatementPayload
	explicitFields, err := json.Marshal(entityStatement(e))
	if err != nil {
		return nil, err
	}
	return extraMarshalHelper(explicitFields, e.Extra)
}

func unmarshalWithExtra(data []byte, target interface{}) (map[string]interface{}, error) {
	if err := json.Unmarshal(data, target); err != nil {
		return nil, err
	}
	extra := make(map[string]interface{})
	if err := json.Unmarshal(data, &extra); err != nil {
		return nil, err
	}
	s := structs.New(target)
	for _, tag := range utils.FieldTagNames(s.Fields(), "json") {
		delete(extra, tag)
	}
	if len(extra) == 0 {
		extra = nil
	}
	return extra, nil
}

// UnmarshalJSON implements the json.Unmarshaler interface.
// It also unmarshalls additional fields into the Extra claim.
func (e *EntityStatementPayload) UnmarshalJSON(data []byte) error {
	type entityStatement EntityStatementPayload
	ee := entityStatement(*e)
	if ee.JWKS == nil {
		ee.JWKS = jwk.NewSet()
	}
	extra, err := unmarshalWithExtra(data, &ee)
	if err != nil {
		return err
	}
	ee.Extra = extra
	*e = EntityStatementPayload(ee)
	return nil
}

// ConstraintSpecification is type for holding constraints according to the oidc fed spec
type ConstraintSpecification struct {
	MaxPathLength          int               `json:"max_path_length,omitempty"`
	NamingConstraints      NamingConstraints `json:"naming_constraints,omitempty"`
	AllowedLeafEntityTypes []string          `json:"allowed_entity_types,omitempty"`
}

// NamingConstraints is a type for holding constraints about naming
type NamingConstraints struct {
	Permitted []string `json:"permitted,omitempty"`
	Excluded  []string `json:"excluded,omitempty"`
}

// AllowedTrustMarkIssuers is type for defining which TrustMark can be issued by which entities
type AllowedTrustMarkIssuers map[string][]string

// TrustMarkOwners defines owners for TrustMarks
type TrustMarkOwners map[string]TrustMarkOwnerSpec

// TrustMarkOwnerSpec describes the owner of a trust mark
type TrustMarkOwnerSpec struct {
	ID   string  `json:"sub"`
	JWKS jwk.Set `json:"jwks"`
}

// UnmarshalJSON implements the json.Unmarshaler interface.
func (tmo *TrustMarkOwnerSpec) UnmarshalJSON(data []byte) error {
	type trustMarkOwner TrustMarkOwnerSpec
	o := trustMarkOwner(*tmo)
	if o.JWKS == nil {
		o.JWKS = jwk.NewSet()
	}
	if err := json.Unmarshal(data, &o); err != nil {
		return err
	}
	*tmo = TrustMarkOwnerSpec(o)
	return nil
}

// ParseEntityStatement parses a jwt into an EntityStatement
func ParseEntityStatement(statementJWT []byte) (*EntityStatement, error) {
	m, err := jws.Parse(statementJWT)
	if err != nil {
		return nil, err
	}
	statement := &EntityStatement{
		jwtMsg:                 m,
		EntityStatementPayload: EntityStatementPayload{},
	}
	if err = json.Unmarshal(m.Payload(), &statement.EntityStatementPayload); err != nil {
		return nil, err
	}
	return statement, err
}
