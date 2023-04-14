package pkg

import (
	"crypto"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/fatih/structs"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/pkg/errors"
)

func signEntityStatement(payload []byte, signingAlg jwa.SignatureAlgorithm, key crypto.Signer) ([]byte, error) {
	headers := jws.NewHeaders()
	if err := headers.Set(jws.TypeKey, "entity-statement+jwt"); err != nil {
		return nil, err
	}
	return jws.Sign(payload, signingAlg, key, jws.WithHeaders(headers))
}

type EntityStatement struct {
	jwtMsg *jws.Message
	EntityStatementPayload
}

func stringsEqaulIfSet(a, b string) bool {
	return a != "" || b != "" || a == b
}

func verifySet(msg *jws.Message, keys jwk.Set) ([]byte, error) {
	var alg jwa.SignatureAlgorithm
	var kid string
	if msg.Signatures() != nil {
		head := msg.Signatures()[0].ProtectedHeaders()
		alg = head.Algorithm()
		kid = head.KeyID()
	}
	buf, err := msg.MarshalJSON()
	if err != nil {
		return nil, err
	}
	if alg == "" && kid == "" {
		return jws.VerifySet(buf, keys)
	}
	for i := 0; i < keys.Len(); i++ {
		k, ok := keys.Get(i)
		if !ok {
			continue
		}
		if !stringsEqaulIfSet(alg.String(), k.Algorithm()) {
			continue
		}
		if !stringsEqaulIfSet(kid, k.KeyID()) {
			continue
		}
		pay, err := jws.Verify(buf, alg, k)
		if err == nil {
			return pay, err
		}
	}
	return nil, errors.New(`failed to verify message with any of the keys in the jwk.Set object`)
}

func (e EntityStatement) Verify(keys jwk.Set) bool {
	_, err := verifySet(e.jwtMsg, keys)
	return err == nil
}

type EntityConfiguration struct {
	EntityStatementPayload
	key crypto.Signer
	jwt []byte
	alg jwa.SignatureAlgorithm
}

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
	e.jwt, err = signEntityStatement(j, e.alg, e.key)
	jwt = e.jwt
	return
}

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

type EntityStatementPayload struct {
	Issuer                           string                   `json:"iss"`
	Subject                          string                   `json:"sub"`
	IssuedAt                         int64                    `json:"iat"`
	ExpiresAt                        int64                    `json:"exp"`
	JWKS                             jwk.Set                  `json:"jwks"`
	Audience                         string                   `json:"aud,omitempty"`
	AuthorityHints                   []string                 `json:"authority_hints,omitempty"`
	Metadata                         *Metadata                `json:"metadata,omitempty"`
	MetadataPolicy                   MetadataPolicies         `json:"metadata_policy,omitempty"`
	Constraints                      *ConstraintSpecification `json:"constraints,omitempty"`
	CriticalExtensions               []string                 `json:"crit,omitempty"`
	CriticalPolicyLanguageExtensions []string                 `json:"policy_language_crit,omitempty"`
	TrustMarks                       []TrustMark              `json:"trust_marks,omitempty"`
	TrustMarksIssuers                *AllowedTrustMarkIssuers `json:"trust_marks_issuers,omitempty"`
	TrustAnchorID                    string                   `json:"trust_anchor_id,omitempty"`
	Extra                            map[string]interface{}   `json:"-"`
}

func (e EntityStatementPayload) TimeValid() bool {
	now := time.Now().Unix()
	return e.IssuedAt <= now && e.ExpiresAt > now
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

func (e EntityStatementPayload) MarshalJSON() ([]byte, error) {
	type entityStatement EntityStatementPayload
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

func (e *EntityStatementPayload) UnmarshalJSON(data []byte) error {
	fmt.Printf("----------\nUnmarshalling\n%s\n----------------\n", data)
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
