package pkg

import (
	"encoding/json"
	"slices"
	"time"

	"github.com/pkg/errors"
	"gopkg.in/yaml.v3"

	"github.com/zachmann/go-oidfed/internal/jwx"
	"github.com/zachmann/go-oidfed/pkg/apimodel"
	"github.com/zachmann/go-oidfed/pkg/jwk"
	"github.com/zachmann/go-oidfed/pkg/unixtime"
)

// TrustMarkInfos is a slice of TrustMarkInfo
type TrustMarkInfos []TrustMarkInfo

// VerifiedFederation verifies all TrustMarkInfos by using the passed trust anchor and returns only the valid TrustMarkInfos
func (tms TrustMarkInfos) VerifiedFederation(ta *EntityStatementPayload) (verified TrustMarkInfos) {
	for _, tm := range tms {
		if err := tm.VerifyFederation(ta); err == nil {
			verified = append(verified, tm)
		}
	}
	return
}

// VerifiedExternal verifies all TrustMarkInfos by using the passed trust mark issuer jwks and optionally the passed
// trust mark owner jwks and returns only the valid TrustMarkInfos
func (tms TrustMarkInfos) VerifiedExternal(jwks jwk.JWKS, tmo ...TrustMarkOwnerSpec) (verified TrustMarkInfos) {
	for _, tm := range tms {
		if err := tm.VerifyExternal(jwks, tmo...); err == nil {
			verified = append(verified, tm)
		}
	}
	return
}

// Find uses the passed function to find the first matching TrustMarkInfo
func (tms TrustMarkInfos) Find(matcher func(info TrustMarkInfo) bool) *TrustMarkInfo {
	for _, tm := range tms {
		if matcher(tm) {
			return &tm
		}
	}
	return nil
}

// FindByID returns the (first) TrustMarkInfo with the passed id
func (tms TrustMarkInfos) FindByID(id string) *TrustMarkInfo {
	return tms.Find(func(info TrustMarkInfo) bool { return info.ID == id })
}

// TrustMarkInfo is a type for holding a trust mark as represented in an EntityConfiguration
type TrustMarkInfo struct {
	ID           string                 `json:"id" yaml:"id"`
	TrustMarkJWT string                 `json:"trust_mark" yaml:"trust_mark"`
	Extra        map[string]interface{} `json:"-" yaml:"-"`
	trustmark    *TrustMark
}

// MarshalJSON implements the json.Marshaler interface.
// It also marshals extra fields.
func (tm TrustMarkInfo) MarshalJSON() ([]byte, error) {
	type trustMarkInfo TrustMarkInfo
	explicitFields, err := json.Marshal(trustMarkInfo(tm))
	if err != nil {
		return nil, err
	}
	return extraMarshalHelper(explicitFields, tm.Extra)
}

// ParseTrustMark parses a trust mark jwt into a TrustMark
func ParseTrustMark(data []byte) (*TrustMark, error) {
	m, err := jwx.Parse(data)
	if err != nil {
		return nil, err
	}
	t := &TrustMark{jwtMsg: m}
	if err = json.Unmarshal(m.Payload(), t); err != nil {
		return nil, err
	}
	return t, nil
}

// UnmarshalJSON implements the json.Unmarshaler interface.
// It also unmarshalls additional fields into the Extra claim.
func (tm *TrustMarkInfo) UnmarshalJSON(data []byte) error {
	type trustMarkInfo TrustMarkInfo
	tmi := trustMarkInfo(*tm)
	extra, err := unmarshalWithExtra(data, &tmi)
	if err != nil {
		return err
	}
	tmi.Extra = extra
	*tm = TrustMarkInfo(tmi)
	return nil
}

// TrustMark returns the TrustMark for this TrustMarkInfo
func (tm *TrustMarkInfo) TrustMark() (*TrustMark, error) {
	if tm.trustmark == nil || tm.trustmark.jwtMsg == nil {
		t, err := ParseTrustMark([]byte(tm.TrustMarkJWT))
		if err != nil {
			return nil, err
		}
		tm.trustmark = t
	}
	return tm.trustmark, nil
}

// VerifyFederation verifies the TrustMarkInfo by using the passed trust anchor
func (tm *TrustMarkInfo) VerifyFederation(ta *EntityStatementPayload) error {
	mark, err := tm.TrustMark()
	if err != nil {
		return err
	}
	if mark.ID != tm.ID {
		return errors.Errorf("trust mark object claim 'id' does not match JWT claim")
	}
	return mark.VerifyFederation(ta)
}

// VerifyExternal verifies the TrustMarkInfo by using the passed trust mark issuer jwks and optionally the passed
// trust mark owner jwks
func (tm *TrustMarkInfo) VerifyExternal(jwks jwk.JWKS, tmo ...TrustMarkOwnerSpec) error {
	mark, err := tm.TrustMark()
	if err != nil {
		return err
	}
	if mark.ID != tm.ID {
		return errors.Errorf("trust mark object claim 'id' does not match JWT claim")
	}
	return mark.VerifyExternal(jwks, tmo...)
}

// TrustMark is a type for holding a trust mark
type TrustMark struct {
	Issuer        string                 `json:"iss"`
	Subject       string                 `json:"sub"`
	ID            string                 `json:"id"`
	IssuedAt      unixtime.Unixtime      `json:"iat"`
	LogoURI       string                 `json:"logo_uri,omitempty"`
	ExpiresAt     *unixtime.Unixtime     `json:"exp,omitempty"`
	Ref           string                 `json:"ref,omitempty"`
	DelegationJWT string                 `json:"delegation,omitempty"`
	Extra         map[string]interface{} `json:"-"`
	jwtMsg        *jwx.ParsedJWT
	delegation    *DelegationJWT
}

// MarshalJSON implements the json.Marshaler interface.
// It also marshals extra fields.
func (tm TrustMark) MarshalJSON() ([]byte, error) {
	type trustMark TrustMark
	explicitFields, err := json.Marshal(trustMark(tm))
	if err != nil {
		return nil, err
	}
	return extraMarshalHelper(explicitFields, tm.Extra)
}

// UnmarshalJSON implements the json.Unmarshaler interface.
// It also unmarshalls additional fields into the Extra claim.
func (tm *TrustMark) UnmarshalJSON(data []byte) error {
	type trustMark TrustMark
	tmi := trustMark(*tm)
	extra, err := unmarshalWithExtra(data, &tmi)
	if err != nil {
		return err
	}
	tmi.Extra = extra
	*tm = TrustMark(tmi)
	return nil
}

func parseDelegationJWT(delegationJWT []byte) (*DelegationJWT, error) {
	m, err := jwx.Parse(delegationJWT)
	if err != nil {
		return nil, err
	}
	d := &DelegationJWT{jwtMsg: m}
	if err = json.Unmarshal(m.Payload(), d); err != nil {
		return nil, err
	}
	return d, nil
}

// Delegation returns the DelegationJWT (if any) for this TrustMark
func (tm *TrustMark) Delegation() (*DelegationJWT, error) {
	var err error
	if tm.delegation == nil {
		if tm.DelegationJWT == "" {
			return nil, nil
		}
		tm.delegation, err = parseDelegationJWT([]byte(tm.DelegationJWT))
	}
	return tm.delegation, err
}

// VerifyFederation verifies the TrustMark by using the passed trust anchor
func (tm *TrustMark) VerifyFederation(ta *EntityStatementPayload) error {
	if tmis, found := ta.TrustMarkIssuers[tm.ID]; found {
		if !slices.Contains(tmis, tm.Issuer) {
			return errors.New("verify trustmark: trust mark issuer is not allowed by trust anchor")
		}
	}
	res, err := DefaultMetadataResolver.ResolveResponsePayload(
		apimodel.ResolveRequest{
			Subject: tm.Issuer,
			Anchor:  []string{ta.Subject},
		},
	)
	if err != nil {
		return errors.Wrap(err, "error while resolving trust mark issuer")
	}
	var tmi *EntityStatement
	if len(res.TrustChain) > 0 {
		tmi, err = ParseEntityStatement(res.TrustChain[0].RawJWT)
	} else {
		tmi, err = GetEntityConfiguration(tm.Issuer)
	}
	if err != nil {
		return errors.Wrap(err, "error while parsing trust mark issuer entity statement")
	}
	if tmi == nil || tmi.JWKS.Len() == 0 {
		return errors.New("no jwks found for trust mark issuer")
	}
	jwks := tmi.JWKS
	tmo, tmoFound := ta.TrustMarkOwners[tm.ID]
	if !tmoFound {
		// no delegation
		return tm.VerifyExternal(jwks)
	}
	return tm.VerifyExternal(jwks, tmo)
}

// VerifyExternal verifies the TrustMark by using the passed trust mark issuer jwks and optionally the passed
// trust mark owner jwks
func (tm *TrustMark) VerifyExternal(jwks jwk.JWKS, tmo ...TrustMarkOwnerSpec) error {
	if err := unixtime.VerifyTime(&tm.IssuedAt, tm.ExpiresAt); err != nil {
		return err
	}
	if _, err := tm.jwtMsg.VerifyWithSet(jwks); err != nil {
		return errors.Wrap(err, "verify trustmark")
	}
	if len(tmo) == 0 {
		// no delegation
		return nil
	}
	// delegation
	delegation, err := tm.Delegation()
	if err != nil {
		return errors.Wrap(err, "verify trustmark: parsing delegation jwt")
	}
	if delegation == nil {
		return errors.New("verify trustmark: no delegation jwt in trust mark")
	}
	if delegation.ID != tm.ID {
		return errors.New("verify trustmark: delegation jwt not for this trust mark")
	}
	if delegation.Subject != tm.Issuer {
		return errors.New("verify trustmark: delegation jwt not for this trust mark issuer")
	}
	if delegation.Issuer != tmo[0].ID {
		return errors.New("verify trustmark: delegation jwt not issued by trust mark owner")
	}
	return delegation.VerifyExternal(tmo[0].JWKS)
}

// DelegationJWT is a type for holding information about a delegation jwt
type DelegationJWT struct {
	Issuer    string                 `json:"iss"`
	Subject   string                 `json:"sub"`
	ID        string                 `json:"id"`
	IssuedAt  unixtime.Unixtime      `json:"iat"`
	ExpiresAt *unixtime.Unixtime     `json:"exp,omitempty"`
	Ref       string                 `json:"ref,omitempty"`
	Extra     map[string]interface{} `json:"-"`
	jwtMsg    *jwx.ParsedJWT
}

// MarshalJSON implements the json.Marshaler interface.
// It also marshals extra fields.
func (djwt DelegationJWT) MarshalJSON() ([]byte, error) {
	type delegationJWT DelegationJWT
	explicitFields, err := json.Marshal(delegationJWT(djwt))
	if err != nil {
		return nil, err
	}
	return extraMarshalHelper(explicitFields, djwt.Extra)
}

// UnmarshalJSON implements the json.Unmarshaler interface.
// It also unmarshalls additional fields into the Extra claim.
func (djwt *DelegationJWT) UnmarshalJSON(data []byte) error {
	type delegationJWT DelegationJWT
	tmi := delegationJWT(*djwt)
	extra, err := unmarshalWithExtra(data, &tmi)
	if err != nil {
		return err
	}
	tmi.Extra = extra
	*djwt = DelegationJWT(tmi)
	return nil
}

// VerifyFederation verifies the DelegationJWT by using the passed trust anchor
func (djwt DelegationJWT) VerifyFederation(ta *EntityStatementPayload) error {
	if err := unixtime.VerifyTime(&djwt.IssuedAt, djwt.ExpiresAt); err != nil {
		return errors.Wrap(err, "verify delegation jwt")
	}
	owner, ok := ta.TrustMarkOwners[djwt.ID]
	if !ok {
		return errors.New("verify delegation jwt: unknown trust mark owner")
	}
	_, err := djwt.jwtMsg.VerifyWithSet(owner.JWKS)
	return errors.Wrap(err, "verify delegation jwt")
}

// VerifyExternal verifies the DelegationJWT by using the passed trust mark owner jwks
func (djwt DelegationJWT) VerifyExternal(jwks jwk.JWKS) error {
	if err := unixtime.VerifyTime(&djwt.IssuedAt, djwt.ExpiresAt); err != nil {
		return errors.Wrap(err, "verify delegation jwt")
	}
	_, err := djwt.jwtMsg.VerifyWithSet(jwks)
	return errors.Wrap(err, "verify delegation jwt")
}

// TrustMarkIssuer is an entity that can issue TrustMarkInfo
type TrustMarkIssuer struct {
	EntityID string
	*TrustMarkSigner
	trustMarks map[string]TrustMarkSpec
}

// TrustMarkSpec describes a TrustMark for a TrustMarkIssuer
type TrustMarkSpec struct {
	ID                       string                     `json:"trust_mark_id" yaml:"trust_mark_id"`
	Lifetime                 unixtime.DurationInSeconds `json:"lifetime" yaml:"lifetime"`
	Ref                      string                     `json:"ref" yaml:"ref"`
	LogoURI                  string                     `json:"logo_uri" yaml:"logo_uri"`
	Extra                    map[string]any             `json:"-" yaml:"-"`
	IncludeExtraClaimsInInfo bool                       `json:"include_extra_claims_in_info" yaml:"include_extra_claims_in_info"`
	DelegationJWT            string                     `json:"delegation_jwt" yaml:"delegation_jwt"`
}

// MarshalJSON implements the json.Marshaler interface
func (tms TrustMarkSpec) MarshalJSON() ([]byte, error) {
	type Alias TrustMarkSpec
	explicitFields, err := json.Marshal(Alias(tms))
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return extraMarshalHelper(explicitFields, tms.Extra)
}

// UnmarshalJSON implements the json.Unmarshaler interface
func (tms *TrustMarkSpec) UnmarshalJSON(data []byte) error {
	type Alias TrustMarkSpec
	mm := Alias(*tms)

	extra, err := unmarshalWithExtra(data, &mm)
	if err != nil {
		return errors.WithStack(err)
	}
	mm.Extra = extra
	*tms = TrustMarkSpec(mm)
	return nil
}

// MarshalYAML implements the yaml.Marshaler interface
func (tms TrustMarkSpec) MarshalYAML() (any, error) {
	type Alias TrustMarkSpec
	explicitFields, err := yaml.Marshal(Alias(tms))
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return yamlExtraMarshalHelper(explicitFields, tms.Extra)
}

// UnmarshalYAML implements the yaml.Unmarshaler interface
func (tms *TrustMarkSpec) UnmarshalYAML(data *yaml.Node) error {
	type Alias TrustMarkSpec
	mm := Alias(*tms)

	extra, err := yamlUnmarshalWithExtra(data, &mm)
	if err != nil {
		return errors.WithStack(err)
	}
	mm.Extra = extra
	*tms = TrustMarkSpec(mm)
	return nil
}

// NewTrustMarkIssuer creates a new TrustMarkIssuer
func NewTrustMarkIssuer(
	entityID string, signer *TrustMarkSigner, trustMarkSpecs []TrustMarkSpec,
) *TrustMarkIssuer {
	trustMarks := make(map[string]TrustMarkSpec, len(trustMarkSpecs))
	for _, tms := range trustMarkSpecs {
		trustMarks[tms.ID] = tms
	}
	return &TrustMarkIssuer{
		EntityID:        entityID,
		TrustMarkSigner: signer,
		trustMarks:      trustMarks,
	}
}

// AddTrustMark adds a TrustMarkSpec to the TrustMarkIssuer enabling it to issue the TrustMarkInfo
func (tmi *TrustMarkIssuer) AddTrustMark(spec TrustMarkSpec) {
	tmi.trustMarks[spec.ID] = spec
}

// TrustMarkIDs returns a slice of the trust mark ids for which this TrustMarKIssuer can issue TrustMarks
func (tmi *TrustMarkIssuer) TrustMarkIDs() []string {
	trustMarkIDs := make([]string, 0, len(tmi.trustMarks))
	for id := range tmi.trustMarks {
		trustMarkIDs = append(trustMarkIDs, id)
	}
	return trustMarkIDs
}

// IssueTrustMark issues a TrustMarkInfo for the passed trust mark id and subject; optionally  a custom lifetime can
// be passed
func (tmi TrustMarkIssuer) IssueTrustMark(trustMarkID, sub string, lifetime ...time.Duration) (*TrustMarkInfo, error) {
	spec, ok := tmi.trustMarks[trustMarkID]
	if !ok {
		return nil, errors.Errorf("unknown trustmark '%s'", trustMarkID)
	}
	now := time.Now()
	tm := &TrustMark{
		Issuer:        tmi.EntityID,
		Subject:       sub,
		ID:            spec.ID,
		IssuedAt:      unixtime.Unixtime{Time: now},
		LogoURI:       spec.LogoURI,
		Ref:           spec.Ref,
		DelegationJWT: spec.DelegationJWT,
		Extra:         spec.Extra,
	}
	lf := spec.Lifetime.Duration
	if len(lifetime) > 0 {
		lf = lifetime[0]
	}
	if lf != 0 {
		tm.ExpiresAt = &unixtime.Unixtime{Time: now.Add(lf)}
	}
	jwt, err := tmi.TrustMarkSigner.JWT(tm)
	if err != nil {
		return nil, err
	}
	var extra map[string]any
	if spec.IncludeExtraClaimsInInfo {
		extra = spec.Extra
	}
	return &TrustMarkInfo{
		ID:           spec.ID,
		TrustMarkJWT: string(jwt),
		Extra:        extra,
		trustmark:    tm,
	}, nil
}

// TrustMarkOwner is a type describing the owning entity of a trust mark; it can be used to issue DelegationJWT
type TrustMarkOwner struct {
	EntityID string
	*TrustMarkDelegationSigner
	ownedTrustMarks map[string]OwnedTrustMark
}

// OwnedTrustMark is a type describing the trust marks owned by a TrustMarkOwner
type OwnedTrustMark struct {
	ID                 string
	DelegationLifetime time.Duration
	Ref                string
	Extra              map[string]any
}

// NewTrustMarkOwner creates a new TrustMarkOwner
func NewTrustMarkOwner(
	entityID string, signer *TrustMarkDelegationSigner, ownedTrustMarks []OwnedTrustMark,
) *TrustMarkOwner {
	trustMarks := make(map[string]OwnedTrustMark, len(ownedTrustMarks))
	for _, tms := range ownedTrustMarks {
		trustMarks[tms.ID] = tms
	}
	return &TrustMarkOwner{
		EntityID:                  entityID,
		TrustMarkDelegationSigner: signer,
		ownedTrustMarks:           trustMarks,
	}
}

// AddTrustMark adds a new OwnedTrustMark to the TrustMarkOwner
func (tmo *TrustMarkOwner) AddTrustMark(spec OwnedTrustMark) {
	tmo.ownedTrustMarks[spec.ID] = spec
}

// DelegationJWT issues a DelegationJWT (as []byte) for the passed trust mark id and subject; optionally a custom
// lifetime can be passed
func (tmo TrustMarkOwner) DelegationJWT(trustMarkID, sub string, lifetime ...time.Duration) ([]byte, error) {
	spec, ok := tmo.ownedTrustMarks[trustMarkID]
	if !ok {
		return nil, errors.Errorf("unknown trustmark '%s'", trustMarkID)
	}
	now := time.Now()
	delegation := &DelegationJWT{
		Issuer:   tmo.EntityID,
		Subject:  sub,
		ID:       spec.ID,
		IssuedAt: unixtime.Unixtime{Time: now},
		Ref:      spec.Ref,
		Extra:    spec.Extra,
	}
	lf := spec.DelegationLifetime
	if len(lifetime) > 0 {
		lf = lifetime[0]
	}
	if spec.DelegationLifetime != 0 {
		delegation.ExpiresAt = &unixtime.Unixtime{Time: now.Add(lf)}
	}
	return tmo.TrustMarkDelegationSigner.JWT(delegation)
}
