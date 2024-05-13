package pkg

import (
	"reflect"

	"github.com/pkg/errors"

	"github.com/zachmann/go-oidfed/internal/utils"
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
	if !utils.ReflectIsSubsetOf(supersetV, subsetV) {
		return errors.Errorf(
			"after combining policies '%s' the '%s' operator values '%v' are not all included in the '%s' operator '%v'",
			pathInfo,
			PolicyOperatorSupersetOf,
			supersetV,
			PolicyOperatorSubsetOf,
			subsetV,
		)
	}
	return nil
}

func policyVerifyAddInSubset(p MetadataPolicyEntry, pathInfo string) error {
	subsetV, subset := p[PolicyOperatorSubsetOf]
	addV, addSet := p[PolicyOperatorAdd]
	if !subset || !addSet {
		return nil
	}
	if !utils.ReflectIsSubsetOf(addV, subsetV) {
		return errors.Errorf(
			"after combining policies '%s' the '%s' operator values '%v' are not all included in the '%s' operator '%v'",
			pathInfo,
			PolicyOperatorAdd,
			addV,
			PolicyOperatorSubsetOf,
			subsetV,
		)
	}
	return nil
}

func policyVerifyDefaultInSubset(p MetadataPolicyEntry, pathInfo string) error {
	subsetV, subset := p[PolicyOperatorSubsetOf]
	defaultV, defaultSet := p[PolicyOperatorDefault]
	if !subset || !defaultSet {
		return nil
	}
	if !utils.ReflectIsSubsetOf(defaultV, subsetV) {
		return errors.Errorf(
			"after combining policies '%s' the '%s' operator values '%v' are not all included in the '%s' operator '%v'",
			pathInfo,
			PolicyOperatorDefault,
			defaultV,
			PolicyOperatorSubsetOf,
			subsetV,
		)
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
	if reflect.ValueOf(addVs).Len() > 1 {
		return errors.Errorf(
			"cannot have multiple values in '%s' operator in combination with '%s' operator for '%s' policy",
			PolicyOperatorAdd, PolicyOperatorOneOf, pathInfo,
		)
	}
	if !utils.ReflectSliceContains(reflect.ValueOf(addVs).Index(0).Interface(), oneOfV) {
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
	if !utils.ReflectIsSupersetOf(defaultV, superV) {
		return errors.Errorf(
			"after combining policies '%s' the '%s' operator values '%v' are not a superset of the '%s' operator '%v'",
			pathInfo,
			PolicyOperatorDefault,
			defaultV,
			PolicyOperatorSupersetOf,
			superV,
		)
	}
	return nil
}

func policyVerifySubsetOfStillHasValues(p MetadataPolicyEntry, pathInfo string) error {
	subsetOf, subsetOfSet := p[PolicyOperatorSubsetOf]
	if !subsetOfSet {
		return nil
	}
	if subsetOf == nil || reflect.ValueOf(utils.Slicify(subsetOf)).Len() == 0 {
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
	if oneOf == nil || reflect.ValueOf(utils.Slicify(oneOf)).Len() == 0 {
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
