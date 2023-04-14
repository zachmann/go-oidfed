package pkg

import (
	"github.com/pkg/errors"
)

type TrustChain []*EntityStatement

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

func (c TrustChain) Metadata() (*Metadata, error) {
	if len(c) == 0 {
		return nil, errors.New("trust chain empty")
	}
	if len(c) == 1 {
		return c[0].Metadata, nil
	}
	combinedPolicy := c[len(c)-1].MetadataPolicy
	metadataPolicies := make([]MetadataPolicies, len(c))
	for i, stmt := range c {
		metadataPolicies[i] = stmt.MetadataPolicy
	}
	combinedPolicy, err := MergeMetadataPolicies(metadataPolicies...)
	if err != nil {
		return nil, err
	}
	return c[0].Metadata.ApplyPolicy(combinedPolicy)
}
