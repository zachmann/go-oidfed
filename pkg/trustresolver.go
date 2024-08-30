package pkg

import (
	"encoding/json"
	"time"

	"github.com/zachmann/go-oidfed/internal"
	"github.com/zachmann/go-oidfed/internal/jwx"
	"github.com/zachmann/go-oidfed/internal/utils"
	"github.com/zachmann/go-oidfed/pkg/cache"
	"github.com/zachmann/go-oidfed/pkg/jwk"
)

type TrustAnchor struct {
	EntityID string   `yaml:"entity_id" json:"entity_id"`
	JWKS     jwk.JWKS `yaml:"jwks" json:"jwks"`
}

type TrustAnchors []TrustAnchor

func (anchors TrustAnchors) EntityIDs() (entityIDs []string) {
	for _, ta := range anchors {
		entityIDs = append(entityIDs, ta.EntityID)
	}
	return
}

func NewTrustAnchorsFromEntityIDs(anchorIDs ...string) (anchors TrustAnchors) {
	for _, id := range anchorIDs {
		anchors = append(anchors, TrustAnchor{EntityID: id})
	}
	return
}

type ResolveResponse struct {
	Issuer     string                 `json:"iss"`
	Subject    string                 `json:"sub"`
	IssuedAt   Unixtime               `json:"iat"`
	ExpiresAt  Unixtime               `json:"exp"`
	Audience   string                 `json:"aud,omitempty"`
	Metadata   *Metadata              `json:"metadata,omitempty"`
	TrustMarks []TrustMarkInfo        `json:"trust_marks,omitempty"`
	TrustChain jwsMessages            `json:"trust_chain,omitempty"`
	Extra      map[string]interface{} `json:"-"`
}

// MarshalJSON implements the json.Marshaler interface.
// It also marshals extra fields.
func (r ResolveResponse) MarshalJSON() ([]byte, error) {
	type resolveResponse ResolveResponse
	explicitFields, err := json.Marshal(resolveResponse(r))
	if err != nil {
		return nil, err
	}
	return extraMarshalHelper(explicitFields, r.Extra)
}

// UnmarshalJSON implements the json.Unmarshaler interface.
// It also unmarshalls additional fields into the Extra claim.
func (r *ResolveResponse) UnmarshalJSON(data []byte) error {
	type resolveResponse ResolveResponse
	var rr resolveResponse
	extra, err := unmarshalWithExtra(data, &rr)
	if err != nil {
		return err
	}
	rr.Extra = extra
	*r = ResolveResponse(rr)
	return nil
}

type jwsMessages []*jwx.ParsedJWT

func (m jwsMessages) MarshalJSON() ([]byte, error) {
	jwts := make([]string, len(m))
	for i, mm := range m {
		jwts[i] = string(mm.RawJWT)
	}
	return json.Marshal(jwts)
}

// TrustResolver is type for resolving trust chains from a StartingEntity to one or multiple TrustAnchors
type TrustResolver struct {
	TrustAnchors   []TrustAnchor
	StartingEntity string
	Type           string
	trustTree      trustTree
}

// ResolveToValidChains starts the trust chain resolution process, building an internal trust tree,
// verifies the signatures, integrity, expirations, and metadata policies and returns all possible valid TrustChains
func (r *TrustResolver) ResolveToValidChains() TrustChains {
	r.Resolve()
	r.VerifySignatures()
	return r.Chains().Filter(TrustChainsFilterValidMetadata)
}

// Resolve starts the trust chain resolution process, building an internal trust tree
func (r *TrustResolver) Resolve() {
	starting, err := GetEntityConfiguration(r.StartingEntity)
	if err != nil {
		return
	}
	if r.Type != "" {
		utils.NilAllButOneByTag(starting.Metadata, r.Type)
	}
	r.trustTree.Entity = starting
	r.trustTree.resolve(r.TrustAnchors)
}

// VerifySignatures verifies the signatures of the internal trust tree
func (r *TrustResolver) VerifySignatures() {
	r.trustTree.verifySignatures(r.TrustAnchors)
}

// Chains returns the TrustChains in the internal trust tree
func (r TrustResolver) Chains() (chains TrustChains) {
	cs := r.trustTree.chains()
	if cs == nil {
		return nil
	}
	for _, c := range cs {
		chains = append(chains, append(TrustChain{r.trustTree.Entity}, c...))
	}
	return
}

// trustTree is a type for holding EntityStatements in a tree
type trustTree struct {
	Entity      *EntityStatement
	Subordinate *EntityStatement
	Authorities []trustTree
}

func (t *trustTree) resolve(anchors TrustAnchors) {
	if t.Entity == nil {
		return
	}
	if utils.SliceContains(t.Entity.Issuer, anchors.EntityIDs()) {
		return
	}
	if len(t.Entity.AuthorityHints) > 0 {
		t.Authorities = make([]trustTree, len(t.Entity.AuthorityHints))
	}
	for i, aID := range t.Entity.AuthorityHints {
		aStmt, err := GetEntityConfiguration(aID)
		if err != nil {
			continue
		}
		if !utils.Equal(aStmt.Issuer, aStmt.Subject, aID) || !aStmt.TimeValid() {
			continue
		}
		if aStmt.Metadata == nil || aStmt.Metadata.FederationEntity == nil || aStmt.Metadata.FederationEntity.
			FederationFetchEndpoint == "" {
			continue
		}
		subordinateStmt, err := FetchEntityStatement(
			aStmt.Metadata.FederationEntity.FederationFetchEndpoint, t.Entity.Issuer, aID,
		)
		if err != nil {
			continue
		}
		if subordinateStmt.Issuer != aID || subordinateStmt.Subject != t.Entity.Issuer || !subordinateStmt.TimeValid() {
			continue
		}
		tt := trustTree{
			Entity:      aStmt,
			Subordinate: subordinateStmt,
		}
		tt.resolve(anchors)
		t.Authorities[i] = tt
	}
}

func (t *trustTree) verifySignatures(anchors TrustAnchors) bool {
	if t.Subordinate != nil {
		for _, ta := range anchors {
			if utils.Equal(ta.EntityID, t.Entity.Issuer, t.Entity.Subject, t.Subordinate.Issuer) {
				// t is about a TA
				jwks := ta.JWKS
				if jwks.Set == nil {
					jwks = t.Entity.JWKS
				}
				return t.Entity.Verify(jwks) && t.Subordinate.Verify(jwks)
			}
		}
	}
	iValid := 0
	for _, tt := range t.Authorities {
		if !tt.verifySignatures(anchors) {
			continue
		}
		// the tt is trusted, getting the JWKS to verify our own signatures
		jwks := tt.Subordinate.JWKS
		if !t.Entity.Verify(jwks) {
			continue
		}
		if t.Subordinate != nil && !t.Subordinate.Verify(jwks) {
			continue
		}
		t.Authorities[iValid] = tt
		iValid++
	}
	t.Authorities = t.Authorities[:iValid]
	return len(t.Authorities) > 0
}

func (t trustTree) chains() (chains []TrustChain) {
	if t.Authorities == nil {
		if t.Subordinate == nil {
			return nil
		}
		return []TrustChain{{t.Subordinate}}
	}
	for _, a := range t.Authorities {
		if t.Subordinate == nil {
			chains = append(chains, a.chains()...)
			continue
		}
		for _, aChain := range a.chains() {
			chains = append(chains, append(TrustChain{t.Subordinate}, aChain...))
		}
	}
	return
}

var entityStatementObtainer internal.EntityStatementObtainer

func init() {
	entityStatementObtainer = internal.DefaultHttpEntityStatementObtainer
}

func entityStmtCacheSet(subID, issID string, stmt *EntityStatement) {
	if err := cache.Set(
		cache.EntityStmtCacheKey(subID, issID), stmt, time.Until(stmt.ExpiresAt.Time),
	); err != nil {
		internal.Log(err)
	}
}
func entityStmtCacheGet(subID, issID string) *EntityStatement {
	var stmt EntityStatement
	set, err := cache.Get(cache.EntityStmtCacheKey(subID, issID), &stmt)
	if err != nil {
		internal.Log(err)
		return nil
	}
	if !set {
		return nil
	}
	return &stmt
}

func GetEntityConfiguration(entityID string) (*EntityStatement, error) {
	if stmt := entityStmtCacheGet(entityID, entityID); stmt != nil {
		internal.Logf("Got entity configuration for %+q from cache", entityID)
		return stmt, nil
	}
	body, err := entityStatementObtainer.GetEntityConfiguration(entityID)
	if err != nil {
		internal.Logf("Could not obtain entity configuration for %+q", entityID)
		return nil, err
	}
	stmt, err := ParseEntityStatement(body)
	if err != nil {
		internal.Logf("Could not parse entity configuration: %s", body)
		return nil, err
	}
	entityStmtCacheSet(entityID, entityID, stmt)
	return stmt, nil
}

func FetchEntityStatement(fetchEndpoint, subID, issID string) (*EntityStatement, error) {
	if stmt := entityStmtCacheGet(subID, issID); stmt != nil {
		return stmt, nil
	}
	body, err := entityStatementObtainer.FetchEntityStatement(fetchEndpoint, subID, issID)
	if err != nil {
		return nil, err
	}
	stmt, err := ParseEntityStatement(body)
	if err != nil {
		return nil, err
	}
	entityStmtCacheSet(subID, issID, stmt)
	return stmt, nil
}
