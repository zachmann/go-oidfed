package pkg

import (
	"crypto"
	"encoding/json"
	"strings"

	"github.com/fatih/structs"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/pkg/errors"
)

var key crypto.Signer
var sign func(payload []byte) ([]byte, error)

func Init(k crypto.Signer, signingAlg jwa.SignatureAlgorithm) {
	key = k
	sign = func(payload []byte) ([]byte, error) {
		headers := jws.NewHeaders()
		if err := headers.Set(jws.TypeKey, "entity-statement+jwt"); err != nil {
			return nil, err
		}
		return jws.Sign(payload, signingAlg, key, jws.WithHeaders(headers))
	}
}

type EntityStatement struct {
	Issuer                           string                   `json:"iss"`
	Subject                          string                   `json:"sub"`
	IssuedAt                         int64                    `json:"iat"`
	ExpiresAt                        int64                    `json:"exp"`
	JWKS                             jwk.Set                  `json:"jwks"`
	Audience                         string                   `json:"aud,omitempty"`
	AuthorityHints                   []string                 `json:"authority_hints,omitempty"`
	Metadata                         *Metadata                `json:"metadata,omitempty"`
	MetadataPolicy                   *MetadataPolicy          `json:"metadata_policy,omitempty"`
	Constraints                      *ConstraintSpecification `json:"constraints,omitempty"`
	CriticalExtensions               []string                 `json:"crit,omitempty"`
	CriticalPolicyLanguageExtensions []string                 `json:"policy_language_crit,omitempty"`
	TrustMarks                       []TrustMark              `json:"trust_marks,omitempty"`
	TrustMarksIssuers                *AllowedTrustMarkIssuers `json:"trust_marks_issuers,omitempty"`
	TrustAnchorID                    string                   `json:"trust_anchor_id,omitempty"`
	Extra                            map[string]interface{}   `json:"-"`
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

func (e EntityStatement) MarshalJSON() ([]byte, error) {
	type entityStatement EntityStatement
	explicitFields, err := json.Marshal(entityStatement(e))
	if err != nil {
		return nil, err
	}
	return extraMarshalHelper(explicitFields, e.Extra)
}

func fieldTagNames(fields []*structs.Field, tag string) (names []string) {
	for _, f := range fields {
		if f == nil {
			continue
		}
		t := f.Tag(tag)
		if i := strings.IndexRune(t, ','); i > 0 {
			t = t[:i]
		}
		if t != "" && t != "-" {
			names = append(names, t)
		}
	}
	return
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
	for _, tag := range fieldTagNames(s.Fields(), "json") {
		delete(extra, tag)
	}
	if len(extra) == 0 {
		extra = nil
	}
	return extra, nil
}

func (e *EntityStatement) UnmarshalJSON(data []byte) error {
	type entityStatement EntityStatement
	ee := entityStatement(*e)
	if ee.JWKS == nil {
		ee.JWKS = jwk.NewSet()
	}
	extra, err := unmarshalWithExtra(data, &ee)
	if err != nil {
		return err
	}
	ee.Extra = extra
	*e = EntityStatement(ee)
	return nil
}

type ConstraintSpecification struct {
	MaxPathLength          int               `json:"max_path_length,omitempty"`
	NamingConstraints      NamingConstraints `json:"naming_constraints,omitempty"`
	AllowedLeafEntityTypes []string          `json:"allowed_leaf_entity_types,omitempty"`
}

type NamingConstraints struct {
	Permitted []string `json:"permitted,omitempty"`
	Excluded  []string `json:"excluded,omitempty"`
}

type AllowedTrustMarkIssuers map[string][]string

func (e EntityStatement) JWT() ([]byte, error) {
	if key == nil {
		return nil, errors.New("no signing key set")
	}
	j, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	return sign(j)
}
