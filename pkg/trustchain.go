package pkg

import (
	"github.com/pkg/errors"
	"tideland.dev/go/slices"

	"github.com/zachmann/go-oidfed/internal/utils"
)

// TrustChain is a slice of *EntityStatements
type TrustChain []*EntityStatement

// ExpiresAt returns the expiration time of the TrustChain as a UNIX time stamp
func (c TrustChain) ExpiresAt() Unixtime {
	if len(c) == 0 {
		return Unixtime{}
	}
	exp := c[0].ExpiresAt
	for i := 1; i < len(c); i++ {
		if e := c[i].ExpiresAt; e.Before(exp.Time) {
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
	critPolicies := make(map[PolicyOperatorName]struct{})
	for i, stmt := range c {
		metadataPolicies[i] = stmt.MetadataPolicy
		for _, mpoc := range stmt.MetadataPolicyCrit {
			critPolicies[mpoc] = struct{}{}
		}
	}
	unsupportedCritPolicies := slices.Subtract(utils.MapKeys(critPolicies), OperatorOrder)
	if len(unsupportedCritPolicies) > 0 {
		return nil, errors.Errorf(
			"the following metadata policy operators are critical but not understood: %v",
			unsupportedCritPolicies,
		)
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
