package pkg

import (
	"reflect"

	"github.com/pkg/errors"

	"github.com/zachmann/go-oidcfed/internal/utils"
)

type PolicyOperator interface {
	Merge(a, b any, pathInfo string) (any, error)
	Apply(value, policyValue any, pathInfo string) (any, error)
	Name() PolicyOperatorName
	IsModifier() bool
}

const (
	PolicyOperatorValue      PolicyOperatorName = "value"
	PolicyOperatorDefault    PolicyOperatorName = "default"
	PolicyOperatorAdd        PolicyOperatorName = "add"
	PolicyOperatorOneOf      PolicyOperatorName = "one_of"
	PolicyOperatorSubsetOf   PolicyOperatorName = "subset_of"
	PolicyOperatorSupersetOf PolicyOperatorName = "superset_of"
	PolicyOperatorEssential  PolicyOperatorName = "essential"
)

var operators map[PolicyOperatorName]PolicyOperator

func RegisterPolicyOperator(operator PolicyOperator) {
	operators[operator.Name()] = operator
}

type policyOperator struct {
	name     PolicyOperatorName
	modifier bool
	merger   func(a, b any, pathInfo string) (any, error)
	applier  func(value, policyValue any, pathInfo string) (any, error)
}

func (op policyOperator) Name() PolicyOperatorName {
	return op.name
}
func (op policyOperator) Merge(a, b any, pathInfo string) (any, error) {
	return op.merger(a, b, pathInfo)
}
func (op policyOperator) Apply(value, policyValue any, pathInfo string) (any, error) {
	return op.applier(value, policyValue, pathInfo)
}
func (op policyOperator) IsModifier() bool {
	return op.modifier
}

func NewPolicyOperator(
	name PolicyOperatorName,
	isModifier bool,
	merger func(a, b any, pathInfo string) (any, error),
	applier func(value, policyValue any, pathInfo string) (any, error),
) PolicyOperator {
	return policyOperator{
		name:     name,
		merger:   merger,
		applier:  applier,
		modifier: isModifier,
	}
}

var policyOperatorAdd = NewPolicyOperator(
	PolicyOperatorAdd,
	true,
	func(a, b any, _ string) (any, error) {
		return utils.ReflectUnion(a, b), nil
	},
	func(value, policyValue any, _ string) (any, error) {
		v := utils.Slicify(value)
		pv := utils.Slicify(policyValue)
		for _, pvv := range pv {
			v = append(v, pvv)
		}
		return v, nil
	},
)

var policyOperatorSubsetOf = NewPolicyOperator(
	PolicyOperatorSubsetOf,
	false,
	func(a, b any, _ string) (any, error) {
		return utils.ReflectIntersect(a, b), nil
	},
	func(value, policyValue any, pathInfo string) (any, error) {
		if reflect.ValueOf(value).IsZero() {
			return value, nil
		}
		v := utils.Slicify(value)
		p := utils.Slicify(policyValue)
		if len(v) != len(utils.ReflectIntersect(v, p)) {
			return value, errors.Errorf("policy operator check failed: '%+v' is not a subset of '%+v'", v, p)
		}
		return value, nil
	},
)

var policyOperatorOneOf = NewPolicyOperator(
	PolicyOperatorOneOf,
	false,
	func(a, b any, _ string) (any, error) {
		return utils.ReflectIntersect(a, b), nil
	},
	func(value, policyValue any, pathInfo string) (any, error) {
		if reflect.ValueOf(value).IsZero() {
			return value, nil
		}
		p := utils.Slicify(policyValue)
		if utils.ReflectSliceContains(value, p) {
			return value, errors.Errorf("policy operator check failed: '%+v' is not a one of '%+v'", value, p)
		}
		return value, nil
	},
)

var policyOperatorSupersetOf = NewPolicyOperator(
	PolicyOperatorSupersetOf,
	false,
	func(a, b any, _ string) (any, error) {
		return utils.ReflectUnion(a, b), nil
	},
	func(value, policyValue any, pathInfo string) (any, error) {
		if reflect.ValueOf(value).IsZero() {
			return value, nil
		}
		v := utils.Slicify(value)
		p := utils.Slicify(policyValue)
		if len(p) != len(utils.ReflectIntersect(v, p)) {
			return value, errors.Errorf("policy operator check failed: '%+v' is not a superset of '%+v'", v, p)
		}
		return value, nil
	},
)

var policyOperatorValue = NewPolicyOperator(
	PolicyOperatorValue,
	true,
	func(a, b any, pathInfo string) (any, error) {
		if reflect.DeepEqual(a, b) {
			return a, nil
		}
		return nil, errors.Errorf(
			"conflicting values '%v' and '%v' when merging '%s' operator in '%s'", a, b, PolicyOperatorValue, pathInfo,
		)
	},
	func(value, policyValue any, pathInfo string) (any, error) {
		if reflect.ValueOf(policyValue).IsZero() {
			return value, nil
		}
		return policyValue, nil
	},
)

var policyOperatorDefault = NewPolicyOperator(
	PolicyOperatorDefault,
	true,
	func(a, b any, pathInfo string) (any, error) {
		if reflect.DeepEqual(a, b) {
			return a, nil
		}
		return nil, errors.Errorf(
			"conflicting values '%v' and '%v' when merging '%s' operator in '%s'", a, b, PolicyOperatorDefault,
			pathInfo,
		)
	},
	func(value, policyValue any, pathInfo string) (any, error) {
		if reflect.ValueOf(value).IsZero() {
			return policyValue, nil
		}
		return value, nil
	},
)

var policyOperatorEssential = NewPolicyOperator(
	PolicyOperatorEssential,
	false,
	func(a, b any, _ string) (any, error) {
		ab, aok := a.(bool)
		bb, bok := b.(bool)
		if !aok && !bok {
			return false, nil
		}
		if !aok {
			return bb, nil
		}
		if !bok {
			return ab, nil
		}
		return ab || bb, nil
	},
	func(value, policyValue any, pathInfo string) (any, error) {
		if essential, eok := policyValue.(bool); eok && essential && reflect.ValueOf(value).IsZero() {
			return nil, errors.Errorf("metadata value for '%s' not set but required", pathInfo)
		}
		return value, nil
	},
)

func init() {
	operators = make(map[PolicyOperatorName]PolicyOperator)
	RegisterPolicyOperator(policyOperatorSubsetOf)
	RegisterPolicyOperator(policyOperatorOneOf)
	RegisterPolicyOperator(policyOperatorSupersetOf)
	RegisterPolicyOperator(policyOperatorAdd)
	RegisterPolicyOperator(policyOperatorValue)
	RegisterPolicyOperator(policyOperatorDefault)
	RegisterPolicyOperator(policyOperatorEssential)
}
