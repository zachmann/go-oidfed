package pkg

import (
	"encoding/json"
	"slices"
	"time"

	"github.com/pkg/errors"

	"github.com/zachmann/go-oidfed/internal/jwx"
	"github.com/zachmann/go-oidfed/pkg/jwk"
)

// TrustMarkInfo is a type for holding a trust mark as represented in an EntityConfiguration
type TrustMarkInfo struct {
	ID           string                 `json:"id"`
	TrustMarkJWT string                 `json:"trust_mark"`
	Extra        map[string]interface{} `json:"-"`
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
		m, err := jwx.Parse([]byte(tm.TrustMarkJWT))
		if err != nil {
			return nil, err
		}
		t := &TrustMark{jwtMsg: m}
		if err = json.Unmarshal(m.Payload(), t); err != nil {
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
	IssuedAt      Unixtime               `json:"iat"`
	LogoURI       string                 `json:"logo_uri,omitempty"`
	ExpiresAt     *Unixtime              `json:"exp,omitempty"`
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
	tmiChains := (&TrustResolver{
		TrustAnchors: []TrustAnchor{
			{
				EntityID: ta.Subject,
				JWKS:     ta.JWKS,
			},
		},
		StartingEntity: tm.Issuer,
	}).ResolveToValidChains()
	if len(tmiChains) == 0 {
		return errors.New("verify trustmark: cannot find valid trustchain for trust mark issuer")
	}
	tmi := tmiChains[0][0]
	tmo, tmoFound := ta.TrustMarkOwners[tm.ID]
	if !tmoFound {
		// no delegation
		return tm.VerifyExternal(tmi.JWKS)
	}
	return tm.VerifyExternal(tmi.JWKS, tmo)
}

// VerifyExternal verifies the TrustMark by using the passed trust mark issuer jwks and optionally the passed
// trust mark owner jwks
func (tm *TrustMark) VerifyExternal(jwks jwk.JWKS, tmo ...TrustMarkOwnerSpec) error {
	if err := verifyTime(&tm.IssuedAt, tm.ExpiresAt); err != nil {
		return err
	}
	if _, err := jwx.VerifyWithSet(tm.jwtMsg, jwks); err != nil {
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
	IssuedAt  Unixtime               `json:"iat"`
	ExpiresAt *Unixtime              `json:"exp,omitempty"`
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
	if err := verifyTime(&djwt.IssuedAt, djwt.ExpiresAt); err != nil {
		return errors.Wrap(err, "verify delegation jwt")
	}
	owner, ok := ta.TrustMarkOwners[djwt.ID]
	if !ok {
		return errors.New("verify delegation jwt: unknown trust mark owner")
	}
	_, err := jwx.VerifyWithSet(djwt.jwtMsg, owner.JWKS)
	return errors.Wrap(err, "verify delegation jwt")
}

// VerifyExternal verifies the DelegationJWT by using the passed trust mark owner jwks
func (djwt DelegationJWT) VerifyExternal(jwks jwk.JWKS) error {
	if err := verifyTime(&djwt.IssuedAt, djwt.ExpiresAt); err != nil {
		return errors.Wrap(err, "verify delegation jwt")
	}
	_, err := jwx.VerifyWithSet(djwt.jwtMsg, jwks)
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
	ID                       string
	Lifetime                 time.Duration
	Ref                      string
	LogoURI                  string
	Extra                    map[string]any
	IncludeExtraClaimsInInfo bool
	DelegationJWT            string
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
		IssuedAt:      Unixtime{now},
		LogoURI:       spec.LogoURI,
		Ref:           spec.Ref,
		DelegationJWT: spec.DelegationJWT,
		Extra:         spec.Extra,
	}
	lf := spec.Lifetime
	if len(lifetime) > 0 {
		lf = lifetime[0]
	}
	if lf != 0 {
		tm.ExpiresAt = &Unixtime{now.Add(lf)}
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
		IssuedAt: Unixtime{now},
		Ref:      spec.Ref,
		Extra:    spec.Extra,
	}
	lf := spec.DelegationLifetime
	if len(lifetime) > 0 {
		lf = lifetime[0]
	}
	if spec.DelegationLifetime != 0 {
		delegation.ExpiresAt = &Unixtime{now.Add(lf)}
	}
	return tmo.TrustMarkDelegationSigner.JWT(delegation)
}
