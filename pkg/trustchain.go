package pkg

import (
	"github.com/pkg/errors"
)

// TrustChain is a slice of *EntityStatements
type TrustChain []*EntityStatement

// ExpiresAt returns the expiration time of the TrustChain as a UNIX time stamp
func (c TrustChain) ExpiresAt() int64 {
	if len(c) == 0 {
		return 0
	}
	exp := c[0].ExpiresAt
	for i := 1; i < len(c); i++ {
		if e := c[i].ExpiresAt; e < exp {
			exp = e
		}
	}
	return exp
}

// Metadata returns the final Metadata for this TrustChain,
// i.e. the Metadata of the leaf entity with MetadataPolicies of authorities applied to it.
func (c TrustChain) Metadata() (*Metadata, error) {
	if len(c) == 0 {
		return nil, errors.New("trust chain empty")
	}
	if len(c) == 1 {
		return c[0].Metadata, nil
	}
	metadataPolicies := make([]*MetadataPolicies, len(c))
	for i, stmt := range c {
		metadataPolicies[i] = stmt.MetadataPolicy
	}
	combinedPolicy, err := MergeMetadataPolicies(metadataPolicies...)
	if err != nil {
		return nil, err
	}
	m := c[0].Metadata
	if m == nil {
		m = &Metadata{}
	}
	return m.ApplyPolicy(combinedPolicy)
}
