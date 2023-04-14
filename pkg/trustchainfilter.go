package pkg

type TrustChains []TrustChain

func (c TrustChains) Filter(filter ...TrustChainsFilter) TrustChains {
	for _, f := range filter {
		c = f(c)
	}
	return c
}

type TrustChainFilterFunc func(TrustChain) bool

type TrustChainsFilter func(TrustChains) TrustChains

func CreateTrustChainsFilter(f TrustChainFilterFunc) TrustChainsFilter {
	return func(chains TrustChains) (final TrustChains) {
		for _, c := range chains {
			if f(c) {
				final = append(final, c)
			}
		}
		return
	}
}

func TrustAnchorFilter(anchor string) TrustChainFilterFunc {
	return func(chain TrustChain) bool {
		if len(chain) == 0 {
			return false
		}
		return chain[len(chain)-1].Issuer == anchor
	}
}

func TrustAnchorChainsFilter(anchor string) TrustChainsFilter {
	return CreateTrustChainsFilter(TrustAnchorFilter(anchor))
}

func MinPathLengthChainsFilter(chains TrustChains) (final TrustChains) {
	min := len(chains[0])
	for i := 1; i < len(chains); i++ {
		if l := len(chains[i]); l < min {
			min = l
		}
	}
	for _, c := range chains {
		if len(c) == min {
			final = append(final, c)
		}
	}
	return
}
