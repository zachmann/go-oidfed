package pkg

import (
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/patrickmn/go-cache"

	"github.com/zachmann/go-oidcfed/internal"
	"github.com/zachmann/go-oidcfed/internal/utils"
)

// TrustResolver is type for resolving trust chains from a StartingEntity to one or multiple TrustAnchors
type TrustResolver struct {
	TrustAnchors   []string
	StartingEntity string
	trustTree      trustTree
}

// ResolveToValidChains starts the trust chain resolution process, building an internal trust tree,
// verifies the signatures, integrity, and expirations and returns all possible valid TrustChains
func (r *TrustResolver) ResolveToValidChains() TrustChains {
	r.Resolve()
	r.trustTree.debugprint(0)
	r.VerifySignatures()
	return r.Chains()
}

// Resolve starts the trust chain resolution process, building an internal trust tree
func (r *TrustResolver) Resolve() {
	starting, err := getEntityConfiguration(r.StartingEntity)
	if err != nil {
		return
	}
	r.trustTree.Entity = starting
	r.trustTree.resolve(r.TrustAnchors)
}

// VerifySignatures verifies the signatures of the internal trust tree
func (r *TrustResolver) VerifySignatures() {
	r.trustTree.verifySignatures(r.TrustAnchors)
}

// Chains returns the TrustChains in the itnernal trust tree
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

// TODO remove
func (t trustTree) debugprint(depth int) {
	if t.Entity == nil {
		return
	}
	p := t.Entity.Issuer
	if t.Subordinate != nil {
		p += fmt.Sprintf(" -> %s", t.Subordinate.Subject)
	}
	fmt.Printf("%s%s\n", strings.Repeat(" ", 4*depth), p)
	for _, tt := range t.Authorities {
		tt.debugprint(depth + 1)
	}
	if depth == 0 {
		fmt.Println()
	}
}

func (t *trustTree) resolve(anchors []string) {
	if t.Entity == nil {
		return
	}
	if utils.SliceContains(t.Entity.Issuer, anchors) {
		return
	}
	if len(t.Entity.AuthorityHints) > 0 {
		t.Authorities = make([]trustTree, len(t.Entity.AuthorityHints))
	}
	for i, aID := range t.Entity.AuthorityHints {
		aStmt, err := getEntityConfiguration(aID)
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
		subordinateStmt, err := fetchEntityStatement(
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

func (t *trustTree) verifySignatures(anchors []string) bool {
	if t.Subordinate != nil && utils.SliceContains(t.Subordinate.Issuer, anchors) {
		return true
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

var entityStatementCache *cache.Cache

func init() {
	entityStatementCache = cache.New(time.Hour, 27*time.Minute)
}

func cacheKey(subID, issID string) string {
	return base64.URLEncoding.EncodeToString([]byte(subID)) + ":" + base64.URLEncoding.EncodeToString([]byte(issID))
}

func entityStmtCacheSet(subID, issID string, stmt *EntityStatement) {
	entityStatementCache.Set(
		cacheKey(subID, issID), stmt, (time.Duration)(stmt.ExpiresAt-time.Now().Unix())*time.Second,
	)
}
func entityStmtCacheGet(subID, issID string) *EntityStatement {
	e, ok := entityStatementCache.Get(cacheKey(subID, issID))
	if !ok {
		return nil
	}
	stmt, ok := e.(*EntityStatement)
	if !ok {
		return nil
	}
	return stmt
}

var entityStatementObtainer internal.EntityStatementObtainer

func init() {
	entityStatementObtainer = internal.DefaultHttpEntityStatementObtainer
}

func getEntityConfiguration(entityID string) (*EntityStatement, error) {
	if stmt := entityStmtCacheGet(entityID, entityID); stmt != nil {
		return stmt, nil
	}
	body, err := entityStatementObtainer.GetEntityConfiguration(entityID)
	if err != nil {
		return nil, err
	}
	stmt, err := ParseEntityStatement(body)
	if err != nil {
		return nil, err
	}
	entityStmtCacheSet(entityID, entityID, stmt)
	return stmt, nil
}

func fetchEntityStatement(fetchEndpoint, subID, issID string) (*EntityStatement, error) {
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
