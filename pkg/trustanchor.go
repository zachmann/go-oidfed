package pkg

import (
	"github.com/go-oidfed/lib/pkg/jwk"
)

// TrustAnchor is a type for specifying trust anchors
type TrustAnchor struct {
	EntityID string   `yaml:"entity_id" json:"entity_id"`
	JWKS     jwk.JWKS `yaml:"jwks" json:"jwks"`
}

// TrustAnchors is a slice of TrustAnchor
type TrustAnchors []TrustAnchor

// EntityIDs returns the entity ids as a []string
func (anchors TrustAnchors) EntityIDs() (entityIDs []string) {
	for _, ta := range anchors {
		entityIDs = append(entityIDs, ta.EntityID)
	}
	return
}

// NewTrustAnchorsFromEntityIDs returns TrustAnchors for the passed entity ids; this does not set jwk.JWKS
func NewTrustAnchorsFromEntityIDs(anchorIDs ...string) (anchors TrustAnchors) {
	for _, id := range anchorIDs {
		anchors = append(anchors, TrustAnchor{EntityID: id})
	}
	return
}
