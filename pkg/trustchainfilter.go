package pkg

// TrustChains is a slice of multiple TrustChain
type TrustChains []TrustChain

// Filter filters multiple TrustChains with the passed TrustChainsFilter to a subset
func (c TrustChains) Filter(filter ...TrustChainsFilter) TrustChains {
	for _, f := range filter {
		c = f.Filter(c)
		if len(c) == 0 {
			break
		}
	}
	return c
}

// TrustChainChecker can check a single TrustChain to determine if it should be included or not,
// i.e. in a TrustChainsFilter
type TrustChainChecker interface {
	Check(TrustChain) bool
}

// TrustChainsFilter filters multiple TrustChains to a subset
type TrustChainsFilter interface {
	Filter(TrustChains) TrustChains
}

// trustChainFilterFromChecker is a TrustChainsFilter that filters TrustChains by applying a TrustChainChecker to
// each TrustChain
type trustChainFilterFromChecker struct {
	TrustChainChecker
}

// Filter implements the TrustChainsFilter interface
func (f trustChainFilterFromChecker) Filter(chains TrustChains) (final TrustChains) {
	if chains == nil {
		return nil
	}
	for _, c := range chains {
		if f.Check(c) {
			final = append(final, c)
		}
	}
	return
}

// NewTrustChainsFilterFromTrustChainChecker creates a new TrustChainsFilter from a TrustChainChecker
func NewTrustChainsFilterFromTrustChainChecker(f TrustChainChecker) TrustChainsFilter {
	return trustChainFilterFromChecker{f}
}

type trustChainChecker struct {
	checker func(chain TrustChain) bool
}

func (c trustChainChecker) Check(chain TrustChain) bool {
	return c.checker(chain)
}

func NewTrustChainsFilterFromCheckerFnc(checker func(TrustChain) bool) TrustChainsFilter {
	return NewTrustChainsFilterFromTrustChainChecker(trustChainChecker{checker: checker})
}

type trustChainsCheckerTrustAnchor struct {
	anchor string
}

// Check implements the TrustChainChecker interface
func (c trustChainsCheckerTrustAnchor) Check(chain TrustChain) bool {
	if len(chain) == 0 {
		return false
	}
	return chain[len(chain)-1].Issuer == c.anchor
}

// TrustChainsFilterTrustAnchor returns a TrustChainsFilter for the passed trust anchor entity id.
// The return TrustChainsFilter will filter TrustChains to only chains ending in the passed anchor.
func TrustChainsFilterTrustAnchor(anchor string) TrustChainsFilter {
	return NewTrustChainsFilterFromTrustChainChecker(trustChainsCheckerTrustAnchor{anchor: anchor})
}

type trustChainsFilterPathLength struct {
	maxPathLen int
}

// Filter implements the TrustChainsFilter interface
func (f trustChainsFilterPathLength) Filter(chains TrustChains) (final TrustChains) {
	if len(chains) == 0 {
		return nil
	}
	if f.maxPathLen < 0 {
		minimum := len(chains[0])
		for i := 1; i < len(chains); i++ {
			if l := len(chains[i]); l < minimum {
				minimum = l
			}
		}
		f.maxPathLen = minimum // skipcq RVV-B0006
	}
	for _, c := range chains {
		if len(c) <= f.maxPathLen {
			final = append(final, c)
		}
	}
	return
}

// TrustChainsFilterMinPathLength is a TrustChainsFilter that filters TrustChains to the chains with the minimal path
// length
var TrustChainsFilterMinPathLength TrustChainsFilter = trustChainsFilterPathLength{maxPathLen: -1}

var TrustChainsFilterValidMetadata TrustChainsFilter = NewTrustChainsFilterFromCheckerFnc(
	func(chain TrustChain) bool {
		_, err := chain.Metadata()
		return err == nil
	},
)

// TrustChainsFilterMaxPathLength returns a TrustChainsFilter that filters TrustChains to only the chains that are
// not longer than the passed maximum path len.
func TrustChainsFilterMaxPathLength(maxPathLen int) TrustChainsFilter {
	return trustChainsFilterPathLength{maxPathLen: maxPathLen}
}
