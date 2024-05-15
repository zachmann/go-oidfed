package pkg

import (
	"reflect"

	"github.com/pkg/errors"

	"github.com/zachmann/go-oidfed/internal/utils"
)

type PolicyOperator interface {
	Merge(a, b any, pathInfo string) (any, error)
	Apply(value, policyValue any, essential bool, pathInfo string) (any, error)
	Name() PolicyOperatorName
	MayCombineWith() []PolicyOperatorName
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

// OperatorOrder defines the order in which the PolicyOperator are applied.
// If custom PolicyOperator are implemented they must be added to this slice at the correct position
var OperatorOrder = []PolicyOperatorName{
	PolicyOperatorValue,
	PolicyOperatorAdd,
	PolicyOperatorDefault,
	PolicyOperatorOneOf,
	PolicyOperatorSubsetOf,
	PolicyOperatorSupersetOf,
	PolicyOperatorEssential,
}

var operators map[PolicyOperatorName]PolicyOperator

func RegisterPolicyOperator(operator PolicyOperator) {
	operators[operator.Name()] = operator
}

type policyOperator struct {
	name        PolicyOperatorName
	merger      func(a, b any, pathInfo string) (any, error)
	applier     func(value, policyValue any, essential bool, pathInfo string) (any, error)
	combineWith []PolicyOperatorName
}

func (op policyOperator) Name() PolicyOperatorName {
	return op.name
}
func (op policyOperator) Merge(a, b any, pathInfo string) (any, error) {
	return op.merger(a, b, pathInfo)
}
func (op policyOperator) Apply(value, policyValue any, essential bool, pathInfo string) (any, error) {
	return op.applier(value, policyValue, essential, pathInfo)
}
func (op policyOperator) MayCombineWith() []PolicyOperatorName {
	return op.combineWith
}

func NewPolicyOperator(
	name PolicyOperatorName,
	merger func(a, b any, pathInfo string) (any, error),
	applier func(value, policyValue any, essential bool, pathInfo string) (any, error),
	mayCombineWith []PolicyOperatorName,
) PolicyOperator {
	return policyOperator{
		name:        name,
		merger:      merger,
		applier:     applier,
		combineWith: mayCombineWith,
	}
}

var policyOperatorAdd = NewPolicyOperator(
	PolicyOperatorAdd,
	func(a, b any, _ string) (any, error) {
		if a == nil {
			return b, nil
		}
		if b == nil {
			return a, nil
		}
		return utils.ReflectUnion(a, b), nil
	},
	func(value, policyValue any, _ bool, _ string) (any, error) {
		if value == nil {
			return policyValue, nil
		}
		if policyValue == nil {
			return value, nil
		}
		return utils.ReflectUnion(value, policyValue), nil
	},
	[]PolicyOperatorName{
		PolicyOperatorDefault,
		PolicyOperatorSubsetOf,
		PolicyOperatorSupersetOf,
		PolicyOperatorEssential,
	},
)

var policyOperatorSubsetOf = NewPolicyOperator(
	PolicyOperatorSubsetOf,
	func(a, b any, _ string) (any, error) {
		if a == nil {
			return b, nil
		}
		if b == nil {
			return a, nil
		}
		return utils.ReflectIntersect(a, b), nil
	},
	func(value, policyValue any, essential bool, pathInfo string) (any, error) {
		if value == nil && !essential {
			return value, nil
		}
		if policyValue == nil {
			return value, nil
		}
		p := utils.Slicify(policyValue)
		if value == nil { // policyValue is not nil and value is essential
			return value, errors.Errorf(
				"policy operator check failed: '%s' not set, but essential and must be one of '%+q'",
				pathInfo, policyValue,
			)
		}
		v := utils.Slicify(value)
		newValue := utils.ReflectIntersect(v, p)
		if reflect.ValueOf(newValue).Len() == 0 {
			newValue = nil
			if essential {
				return newValue, errors.Errorf(
					"policy operator check failed for '%s': '%+q' is not subset of '%+q' but essential",
					pathInfo, value, p,
				)
			}
		}
		return newValue, nil
	},
	[]PolicyOperatorName{
		PolicyOperatorAdd,
		PolicyOperatorDefault,
		PolicyOperatorSupersetOf,
		PolicyOperatorEssential,
	},
)

var policyOperatorOneOf = NewPolicyOperator(
	PolicyOperatorOneOf,
	func(a, b any, _ string) (any, error) {
		if a == nil {
			return b, nil
		}
		if b == nil {
			return a, nil
		}
		return utils.ReflectIntersect(a, b), nil
	},
	func(value, policyValue any, essential bool, pathInfo string) (any, error) {
		if value == nil && !essential {
			return value, nil
		}
		if policyValue == nil {
			return value, nil
		}
		p := utils.Slicify(policyValue)
		if value == nil { // policyValue is not nil and value is essential
			return value, errors.Errorf(
				"policy operator check failed: '%s' not set, but essential and must be one of '%+q'",
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
	[]PolicyOperatorName{
		PolicyOperatorDefault,
		PolicyOperatorEssential,
	},
)

var policyOperatorSupersetOf = NewPolicyOperator(
	PolicyOperatorSupersetOf,
	func(a, b any, _ string) (any, error) {
		if a == nil {
			return b, nil
		}
		if b == nil {
			return a, nil
		}
		return utils.ReflectUnion(a, b), nil
	},
	func(value, policyValue any, essential bool, pathInfo string) (any, error) {
		if value == nil && !essential {
			return value, nil
		}
		if policyValue == nil {
			return value, nil
		}
		p := utils.Slicify(policyValue)
		if value == nil { // policyValue is not nil and value is essential
			return value, errors.Errorf(
				"policy operator check failed: '%s' not set, but essential and must be superset of '%+q'",
				pathInfo, policyValue,
			)
		}

		v := utils.Slicify(value)
		if !utils.ReflectIsSupersetOf(v, p) {
			return value, errors.Errorf(
				"policy operator check failed for '%s': '%+q' is not a superset of '%+q'",
				pathInfo, v, p,
			)
		}
		return value, nil
	},
	[]PolicyOperatorName{
		PolicyOperatorAdd,
		PolicyOperatorDefault,
		PolicyOperatorSubsetOf,
		PolicyOperatorEssential,
	},
)

var policyOperatorValue = NewPolicyOperator(
	PolicyOperatorValue,
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
	func(value, policyValue any, _ bool, pathInfo string) (any, error) {
		if policyValue == nil {
			return value, nil
		}
		return utils.ReflectSliceCast(policyValue, utils.Slicify(value)), nil
	},
	[]PolicyOperatorName{PolicyOperatorEssential},
)

var policyOperatorDefault = NewPolicyOperator(
	PolicyOperatorDefault,
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
	func(value, policyValue any, _ bool, pathInfo string) (any, error) {
		if value == nil || reflect.ValueOf(value).IsZero() {
			return utils.ReflectSliceCast(policyValue, utils.Slicify(value)), nil
		}
		return value, nil
	},
	[]PolicyOperatorName{
		PolicyOperatorAdd,
		PolicyOperatorOneOf,
		PolicyOperatorSubsetOf,
		PolicyOperatorSupersetOf,
		PolicyOperatorEssential,
	},
)

var policyOperatorEssential = NewPolicyOperator(
	PolicyOperatorEssential,
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
	func(value, policyValue any, _ bool, pathInfo string) (any, error) {
		if policyValue == nil {
			return value, nil
		}
		if essential, eok := policyValue.(bool); eok && essential && (value == nil || reflect.ValueOf(value).IsZero()) {
			return nil, errors.Errorf("metadata value for '%s' not set but required", pathInfo)
		}
		return value, nil
	},
	nil,
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
