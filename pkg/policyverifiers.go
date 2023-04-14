package pkg

import (
	"github.com/pkg/errors"

	"github.com/zachmann/go-oidcfed/internal/utils"
)

type PolicyVerifier func(p MetadataPolicyEntry, pathInfo string) error

var policyVerifiers []PolicyVerifier

func RegisterPolicyVerifier(v PolicyVerifier) {
	policyVerifiers = append(policyVerifiers, v)
}

func policyVerifierSubsetSupersetOneOf(p MetadataPolicyEntry, pathInfo string) error {
	_, oneof := p[PolicyOperatorOneOf]
	_, subset := p[PolicyOperatorSubsetOf]
	_, superset := p[PolicyOperatorSupersetOf]
	if oneof && (subset || superset) {
		return errors.Errorf(
			"policy_operator '%s' cannot appear beside '%s'/'%s' in policy entry '%s'",
			PolicyOperatorOneOf, PolicyOperatorSubsetOf, PolicyOperatorSupersetOf, pathInfo,
		)
	}
	return nil
}

func policyVerifierSubsetSupersetOf(p MetadataPolicyEntry, pathInfo string) error {
	subsetV, subset := p[PolicyOperatorSubsetOf]
	supersetV, superset := p[PolicyOperatorSupersetOf]
	if !subset || !superset {
		return nil
	}
	subsetVs := utils.Slicify(subsetV)
	supersetVs := utils.Slicify(supersetV)
	for _, super := range supersetVs {
		if !utils.ReflectSliceContains(super, subsetVs) {
			return errors.Errorf(
				"after combining policies '%s' the '%s' operator value '%v' is not included in the '%s' operator",
				pathInfo,
				PolicyOperatorSupersetOf,
				super,
				PolicyOperatorSubsetOf,
			)
		}
	}
	return nil
}

func policyVerifyAddInSubset(p MetadataPolicyEntry, pathInfo string) error {
	subsetV, subset := p[PolicyOperatorSubsetOf]
	addV, addSet := p[PolicyOperatorAdd]
	if !subset || !addSet {
		return nil
	}
	subsetVs := utils.Slicify(subsetV)
	addVs := utils.Slicify(addV)
	for _, a := range addVs {
		if !utils.ReflectSliceContains(a, subsetVs) {
			return errors.Errorf(
				"after combining policies '%s' the '%s' operator value '%v' is not included in the '%s' operator",
				pathInfo,
				PolicyOperatorAdd,
				a,
				PolicyOperatorSubsetOf,
			)
		}
	}
	return nil
}

func policyVerifyDefaultInSubset(p MetadataPolicyEntry, pathInfo string) error {
	subsetV, subset := p[PolicyOperatorSubsetOf]
	defaultV, defaultSet := p[PolicyOperatorDefault]
	if !subset || !defaultSet {
		return nil
	}
	subsetVs := utils.Slicify(subsetV)
	defaultVs := utils.Slicify(defaultV)
	for _, d := range defaultVs {
		if !utils.ReflectSliceContains(d, subsetVs) {
			return errors.Errorf(
				"after combining policies '%s' the '%s' operator value '%v' is not included in the '%s' operator",
				pathInfo,
				PolicyOperatorDefault,
				d,
				PolicyOperatorSubsetOf,
			)
		}
	}
	return nil
}

func policyVerifyAddInOneOf(p MetadataPolicyEntry, pathInfo string) error {
	oneOfV, oneOf := p[PolicyOperatorOneOf]
	addV, addSet := p[PolicyOperatorAdd]
	if !oneOf || !addSet {
		return nil
	}
	addVs := utils.Slicify(addV)
	if len(addVs) > 1 {
		return errors.Errorf(
			"cannot have multiple values in '%s' operator in combination with '%s' operator for '%s' policy",
			PolicyOperatorAdd, PolicyOperatorOneOf, pathInfo,
		)
	}
	oneOfVs := utils.Slicify(oneOfV)
	if !utils.ReflectSliceContains(addVs[0], oneOfVs) {
		return errors.Errorf(
			"after combining policies '%s' the '%s' operator value '%v' is not included in the '%s' operator",
			pathInfo,
			PolicyOperatorAdd,
			addV,
			PolicyOperatorOneOf,
		)
	}
	return nil
}

func policyVerifyDefaultInOneOf(p MetadataPolicyEntry, pathInfo string) error {
	oneOfV, oneOf := p[PolicyOperatorOneOf]
	defaultV, defaultSet := p[PolicyOperatorDefault]
	if !oneOf || !defaultSet {
		return nil
	}
	oneOfVs := utils.Slicify(oneOfV)
	if !utils.ReflectSliceContains(defaultV, oneOfVs) {
		return errors.Errorf(
			"after combining policies '%s' the '%s' operator value '%v' is not included in the '%s' operator",
			pathInfo,
			PolicyOperatorDefault,
			defaultV,
			PolicyOperatorOneOf,
		)
	}
	return nil
}

func policyVerifyDefaultSuperset(p MetadataPolicyEntry, pathInfo string) error {
	superV, superset := p[PolicyOperatorSupersetOf]
	defaultV, defaultSet := p[PolicyOperatorDefault]
	if !superset || !defaultSet {
		return nil
	}
	superVs := utils.Slicify(superV)
	defaultVs := utils.Slicify(defaultV)
	for _, s := range superVs {
		if !utils.ReflectSliceContains(s, defaultVs) {
			return errors.Errorf(
				"after combining policies '%s' the '%s' operator value '%v' is not included in the '%s' operator",
				pathInfo,
				PolicyOperatorSupersetOf,
				s,
				PolicyOperatorDefault,
			)
		}
	}
	return nil
}

func policyVerifySubsetOfStillHasValues(p MetadataPolicyEntry, pathInfo string) error {
	subsetOf, subsetOfSet := p[PolicyOperatorSubsetOf]
	if !subsetOfSet {
		return nil
	}
	if len(utils.Slicify(subsetOf)) == 0 {
		return errors.Errorf(
			"policy_operator '%s' has no valid value after combining policies '%s'",
			PolicyOperatorSubsetOf, pathInfo,
		)
	}
	return nil
}

func policyVerifyOneOfStillHasValues(p MetadataPolicyEntry, pathInfo string) error {
	oneOf, oneOfSet := p[PolicyOperatorOneOf]
	if !oneOfSet {
		return nil
	}
	if len(utils.Slicify(oneOf)) == 0 {
		return errors.Errorf(
			"policy_operator '%s' has no valid value after combining policies '%s'",
			PolicyOperatorOneOf, pathInfo,
		)
	}
	return nil
}

func init() {
	RegisterPolicyVerifier(policyVerifierSubsetSupersetOneOf)
	RegisterPolicyVerifier(policyVerifierSubsetSupersetOf)
	RegisterPolicyVerifier(policyVerifyAddInSubset)
	RegisterPolicyVerifier(policyVerifyAddInOneOf)
	RegisterPolicyVerifier(policyVerifyDefaultInOneOf)
	RegisterPolicyVerifier(policyVerifyDefaultInSubset)
	RegisterPolicyVerifier(policyVerifyDefaultSuperset)
	RegisterPolicyVerifier(policyVerifySubsetOfStillHasValues)
	RegisterPolicyVerifier(policyVerifyOneOfStillHasValues)
}
