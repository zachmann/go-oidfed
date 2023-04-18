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
		if a == nil {
			return b, nil
		}
		if b == nil {
			return a, nil
		}
		return utils.ReflectUnion(a, b), nil
	},
	func(value, policyValue any, _ string) (any, error) {
		if value == nil {
			return policyValue, nil
		}
		if policyValue == nil {
			return value, nil
		}
		v := utils.Slicify(value)
		pv := utils.Slicify(policyValue)
		for _, pvv := range pv {
			if !utils.ReflectSliceContains(pvv, v) {
				v = append(v, pvv)
			}
		}
		return v, nil
	},
)

var policyOperatorSubsetOf = NewPolicyOperator(
	PolicyOperatorSubsetOf,
	false,
	func(a, b any, _ string) (any, error) {
		if a == nil {
			return b, nil
		}
		if b == nil {
			return a, nil
		}
		return utils.ReflectIntersect(a, b), nil
	},
	func(value, policyValue any, pathInfo string) (any, error) {
		if policyValue == nil {
			return value, nil
		}
		p := utils.Slicify(policyValue)
		if value == nil { // policyValue is not nil
			if len(p) == 0 {
				return value, nil
			}
			return value, errors.Errorf(
				"policy operator check failed: '%s' not set, but must be subset of '%+q'",
				pathInfo, policyValue,
			)
		}
		v := utils.Slicify(value)
		if len(v) != len(utils.ReflectIntersect(v, p)) {
			return value, errors.Errorf(
				"policy operator check failed for '%s': '%+q' is not a subset of '%+q'",
				pathInfo, v, p,
			)
		}
		return value, nil
	},
)

var policyOperatorOneOf = NewPolicyOperator(
	PolicyOperatorOneOf,
	false,
	func(a, b any, _ string) (any, error) {
		if a == nil {
			return b, nil
		}
		if b == nil {
			return a, nil
		}
		return utils.ReflectIntersect(a, b), nil
	},
	func(value, policyValue any, pathInfo string) (any, error) {
		if policyValue == nil {
			return value, nil
		}
		p := utils.Slicify(policyValue)
		if value == nil { // policyValue is not nil
			if len(p) == 0 {
				return value, nil
			}
			return value, errors.Errorf(
				"policy operator check failed: '%s' not set, but must be one of '%+q'",
				pathInfo, policyValue,
			)
		}
		if !utils.ReflectSliceContains(value, p) {
			return value, errors.Errorf(
				"policy operator check failed for '%s': '%+q' is not one of '%+q'",
				pathInfo, value, p,
			)
		}
		return value, nil
	},
)

var policyOperatorSupersetOf = NewPolicyOperator(
	PolicyOperatorSupersetOf,
	false,
	func(a, b any, _ string) (any, error) {
		if a == nil {
			return b, nil
		}
		if b == nil {
			return a, nil
		}
		return utils.ReflectUnion(a, b), nil
	},
	func(value, policyValue any, pathInfo string) (any, error) {
		if policyValue == nil {
			return value, nil
		}
		p := utils.Slicify(policyValue)
		if value == nil { // policyValue is not nil
			if len(p) == 0 {
				return value, nil
			}
			return value, errors.Errorf(
				"policy operator check failed: '%s' not set, but must be superset of '%+q'",
				pathInfo, policyValue,
			)
		}

		v := utils.Slicify(value)
		if len(p) != len(utils.ReflectIntersect(v, p)) {
			return value, errors.Errorf(
				"policy operator check failed for '%s': '%+q' is not a superset of '%+q'",
				pathInfo, v, p,
			)
		}
		return value, nil
	},
)

var policyOperatorValue = NewPolicyOperator(
	PolicyOperatorValue,
	true,
	func(a, b any, pathInfo string) (any, error) {
		if a == nil {
			return b, nil
		}
		if b == nil {
			return a, nil
		}
		if utils.SliceEqual(a, b) {
			return a, nil
		}
		return nil, errors.Errorf(
			"conflicting values '%v' and '%v' when merging '%s' operator in '%s'", a, b, PolicyOperatorValue, pathInfo,
		)
	},
	func(value, policyValue any, pathInfo string) (any, error) {
		if policyValue == nil {
			return value, nil
		}
		return policyValue, nil
	},
)

var policyOperatorDefault = NewPolicyOperator(
	PolicyOperatorDefault,
	true,
	func(a, b any, pathInfo string) (any, error) {
		if a == nil {
			return b, nil
		}
		if b == nil {
			return a, nil
		}
		if utils.SliceEqual(a, b) {
			return a, nil
		}
		return nil, errors.Errorf(
			"conflicting values '%v' and '%v' when merging '%s' operator in '%s'", a, b, PolicyOperatorDefault,
			pathInfo,
		)
	},
	func(value, policyValue any, pathInfo string) (any, error) {
		if value == nil || reflect.ValueOf(value).IsZero() {
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
		if policyValue == nil {
			return value, nil
		}
		if essential, eok := policyValue.(bool); eok && essential && (value == nil || reflect.ValueOf(value).IsZero()) {
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
