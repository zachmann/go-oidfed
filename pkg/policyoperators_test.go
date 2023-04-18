package pkg

import (
	"testing"

	"github.com/zachmann/go-oidcfed/internal/utils"
)

func TestPolicyOperatorAddMerge(t *testing.T) {
	tests := []struct {
		name        string
		a           any
		b           any
		pathInfo    string
		expected    any
		errExpected bool
	}{
		{
			name:        "both nil",
			a:           nil,
			b:           nil,
			pathInfo:    "test",
			expected:    nil,
			errExpected: false,
		},
		{
			name:        "both empty slices",
			a:           []string{},
			b:           []string{},
			pathInfo:    "test",
			expected:    []string{},
			errExpected: false,
		},
		{
			name:        "string + nil",
			a:           "value",
			b:           nil,
			pathInfo:    "test",
			expected:    "value",
			errExpected: false,
		},
		{
			name:        "string + empty slice",
			a:           "value",
			b:           []string{},
			pathInfo:    "test",
			expected:    "value",
			errExpected: false,
		},
		{
			name:     "string + string",
			a:        "value",
			b:        "other",
			pathInfo: "test",
			expected: []string{
				"value",
				"other",
			},
			errExpected: false,
		},
		{
			name: "string + slice",
			a:    "value",
			b: []string{
				"other",
				"values",
			},
			pathInfo: "test",
			expected: []string{
				"value",
				"other",
				"values",
			},
			errExpected: false,
		},
		{
			name: "slice + slice",
			a:    []string{"value"},
			b: []string{
				"other",
				"values",
			},
			pathInfo: "test",
			expected: []string{
				"value",
				"other",
				"values",
			},
			errExpected: false,
		},
		{
			name: "slice + slice with duplicates",
			a: []string{
				"value",
				"values",
			},
			b: []string{
				"other",
				"values",
				"value",
			},
			pathInfo: "test",
			expected: []string{
				"value",
				"values",
				"other",
			},
			errExpected: false,
		},
		{
			name: "nil + slice",
			a:    nil,
			b: []string{
				"other",
				"values",
				"value",
			},
			pathInfo: "test",
			expected: []string{
				"other",
				"values",
				"value",
			},
			errExpected: false,
		},
		{
			name: "slice + nil",
			a: []string{
				"other",
				"values",
				"value",
			},
			b:        nil,
			pathInfo: "test",
			expected: []string{
				"other",
				"values",
				"value",
			},
			errExpected: false,
		},
		{
			name: "empty slice + slice",
			a:    []string{},
			b: []string{
				"other",
				"values",
				"value",
			},
			pathInfo: "test",
			expected: []string{
				"other",
				"values",
				"value",
			},
			errExpected: false,
		},
		{
			name: "slice + empty slice",
			a: []string{
				"other",
				"values",
				"value",
			},
			b:        []string{},
			pathInfo: "test",
			expected: []string{
				"other",
				"values",
				"value",
			},
			errExpected: false,
		},
	}
	op := policyOperatorAdd
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				merged, err := op.Merge(test.a, test.b, test.pathInfo)
				if err != nil {
					if test.errExpected {
						return
					}
					t.Errorf("did not expect error, but did not verify correctly")
				} else if test.errExpected {
					t.Errorf("expected error, but verified correctly")
				}
				if !utils.SliceEqual(test.expected, merged) {
					t.Errorf("expected merged object to be '%+q', but got '%+q' instead", test.expected, merged)
				}
			},
		)
	}
}

func TestPolicyOperatorAddApply(t *testing.T) {
	tests := []struct {
		name        string
		value       any
		policyValue any
		pathInfo    string
		expected    any
		errExpected bool
	}{
		{
			name:        "both nil",
			value:       nil,
			policyValue: nil,
			pathInfo:    "test",
			expected:    nil,
			errExpected: false,
		},
		{
			name:        "value nil, policy string",
			value:       nil,
			policyValue: "value",
			pathInfo:    "test",
			expected:    "value",
			errExpected: false,
		},
		{
			name:  "value nil, policy slice",
			value: nil,
			policyValue: []string{
				"value",
				"other",
			},
			pathInfo: "test",
			expected: []string{
				"value",
				"other",
			},
			errExpected: false,
		},
		{
			name:        "value string, policy string",
			value:       "value",
			policyValue: "other",
			pathInfo:    "test",
			expected: []string{
				"value",
				"other",
			},
			errExpected: false,
		},
		{
			name:  "value string, policy slice",
			value: "value",
			policyValue: []string{
				"additional",
				"other",
			},
			pathInfo: "test",
			expected: []string{
				"value",
				"additional",
				"other",
			},
			errExpected: false,
		},
		{
			name:        "value string, policy string dupl",
			value:       "value",
			policyValue: "value",
			pathInfo:    "test",
			expected:    "value",
			errExpected: false,
		},
		{
			name:  "value string, policy slice dupl",
			value: "value",
			policyValue: []string{
				"value",
				"other",
			},
			pathInfo: "test",
			expected: []string{
				"value",
				"other",
			},
			errExpected: false,
		},
		{
			name:        "value empty slice, policy string",
			value:       []string{},
			policyValue: "value",
			pathInfo:    "test",
			expected:    []string{"value"},
			errExpected: false,
		},
		{
			name:  "value empty slice, policy slice",
			value: []string{},
			policyValue: []string{
				"value",
				"other",
			},
			pathInfo: "test",
			expected: []string{
				"value",
				"other",
			},
			errExpected: false,
		},
		{
			name:        "value slice, policy string",
			value:       []string{"value"},
			policyValue: "add",
			pathInfo:    "test",
			expected: []string{
				"value",
				"add",
			},
			errExpected: false,
		},
		{
			name: "value slice, policy slice",
			value: []string{
				"value",
				"more",
			},
			policyValue: []string{
				"value",
				"other",
			},
			pathInfo: "test",
			expected: []string{
				"value",
				"more",
				"other",
			},
			errExpected: false,
		},
	}
	op := policyOperatorAdd
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				result, err := op.Apply(test.value, test.policyValue, test.pathInfo)
				if err != nil {
					if test.errExpected {
						return
					}
					t.Errorf("did not expect error, but did not verify correctly")
				} else if test.errExpected {
					t.Errorf("expected error, but verified correctly")
				}
				if !utils.SliceEqual(test.expected, result) {
					t.Errorf("expected resulting object to be '%+q', but got '%+q' instead", test.expected, result)
				}
			},
		)
	}
}

func TestPolicyOperatorSubsetOfMerge(t *testing.T) {
	tests := []struct {
		name        string
		a           any
		b           any
		pathInfo    string
		expected    any
		errExpected bool
	}{
		{
			name:        "both nil",
			a:           nil,
			b:           nil,
			pathInfo:    "test",
			expected:    nil,
			errExpected: false,
		},
		{
			name:        "both empty",
			a:           []string{},
			b:           []string{},
			pathInfo:    "test",
			expected:    []string{},
			errExpected: false,
		},
		{
			name: "one nil",
			a:    nil,
			b: []string{
				"a",
				"b",
			},
			pathInfo: "test",
			expected: []string{
				"a",
				"b",
			},
			errExpected: false,
		},
		{
			name: "one empty",
			a:    []string{},
			b: []string{
				"a",
				"b",
			},
			pathInfo:    "test",
			expected:    []string{},
			errExpected: false,
		},
		{
			name: "equal",
			a: []string{
				"a",
				"b",
			},
			b: []string{
				"a",
				"b",
			},
			pathInfo: "test",
			expected: []string{
				"a",
				"b",
			},
			errExpected: false,
		},
		{
			name: "subset",
			a: []string{
				"a",
				"b",
				"c",
			},
			b: []string{
				"b",
				"c",
				"d",
			},
			pathInfo: "test",
			expected: []string{
				"b",
				"c",
			},
			errExpected: false,
		},
		{
			name: "distinct",
			a: []string{
				"a",
				"b",
			},
			b: []string{
				"c",
				"d",
			},
			pathInfo:    "test",
			expected:    []string{},
			errExpected: false,
		},
	}
	op := policyOperatorSubsetOf
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				merged, err := op.Merge(test.a, test.b, test.pathInfo)
				if err != nil {
					if test.errExpected {
						return
					}
					t.Errorf("did not expect error, but did not verify correctly")
				} else if test.errExpected {
					t.Errorf("expected error, but verified correctly")
				}
				if !utils.SliceEqual(test.expected, merged) {
					t.Errorf("expected merged object to be '%+q', but got '%+q' instead", test.expected, merged)
				}
			},
		)
	}
}

func TestPolicyOperatorSubsetOfApply(t *testing.T) {
	tests := []struct {
		name        string
		value       any
		policyValue any
		pathInfo    string
		expected    any
		errExpected bool
	}{
		{
			name:        "both nil",
			value:       nil,
			policyValue: nil,
			pathInfo:    "test",
			expected:    nil,
			errExpected: false,
		},
		{
			name:  "value nil",
			value: nil,
			policyValue: []string{
				"a",
				"b",
			},
			pathInfo:    "test",
			expected:    nil,
			errExpected: true,
		},
		{
			name: "policy nil",
			value: []string{
				"a",
				"b",
			},
			policyValue: nil,
			pathInfo:    "test",
			expected: []string{
				"a",
				"b",
			},
			errExpected: false,
		},
		{
			name: "equal",
			value: []string{
				"a",
				"b",
			},
			policyValue: []string{
				"a",
				"b",
			},
			pathInfo: "test",
			expected: []string{
				"a",
				"b",
			},
			errExpected: false,
		},
		{
			name: "subset",
			value: []string{
				"a",
				"b",
			},
			policyValue: []string{
				"a",
				"b",
				"c",
			},
			pathInfo: "test",
			expected: []string{
				"a",
				"b",
			},
			errExpected: false,
		},
		{
			name: "no subset",
			value: []string{
				"a",
				"b",
				"c",
				"d",
			},
			policyValue: []string{
				"a",
				"b",
				"c",
			},
			pathInfo:    "test",
			errExpected: true,
		},
		{
			name: "distinct",
			value: []string{
				"a",
				"b",
			},
			policyValue: []string{
				"c",
				"d",
			},
			pathInfo:    "test",
			errExpected: true,
		},
	}
	op := policyOperatorSubsetOf
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				result, err := op.Apply(test.value, test.policyValue, test.pathInfo)
				if err != nil {
					if test.errExpected {
						return
					}
					t.Errorf("did not expect error, but did not verify correctly")
				} else if test.errExpected {
					t.Errorf("expected error, but verified correctly")
				}
				if !utils.SliceEqual(test.expected, result) {
					t.Errorf("expected resulting object to be '%+q', but got '%+q' instead", test.expected, result)
				}
			},
		)
	}
}

func TestPolicyOperatorOneOfMerge(t *testing.T) {
	tests := []struct {
		name        string
		a           any
		b           any
		pathInfo    string
		expected    any
		errExpected bool
	}{
		{
			name:        "both nil",
			a:           nil,
			b:           nil,
			pathInfo:    "test",
			expected:    nil,
			errExpected: false,
		},
		{
			name: "a nil",
			a: []string{
				"a",
				"b",
			},
			b:        nil,
			pathInfo: "test",
			expected: []string{
				"a",
				"b",
			},
			errExpected: false,
		},
		{
			name: "b nil",
			a:    nil,
			b: []string{
				"a",
				"b",
			},
			pathInfo: "test",
			expected: []string{
				"a",
				"b",
			},
			errExpected: false,
		},
		{
			name:        "both empty",
			a:           []string{},
			b:           []string{},
			pathInfo:    "test",
			expected:    []string{},
			errExpected: false,
		},
		{
			name: "one empty",
			a: []string{
				"a",
				"b",
			},
			b:           []string{},
			pathInfo:    "test",
			expected:    []string{},
			errExpected: false,
		},
		{
			name: "distinct",
			a: []string{
				"a",
				"b",
			},
			b: []string{
				"c",
				"d",
			},
			pathInfo:    "test",
			expected:    []string{},
			errExpected: false,
		},
		{
			name: "equal",
			a: []string{
				"a",
				"b",
			},
			b: []string{
				"a",
				"b",
			},
			pathInfo: "test",
			expected: []string{
				"a",
				"b",
			},
			errExpected: false,
		},
		{
			name: "intersect",
			a: []string{
				"a",
				"b",
				"c",
			},
			b: []string{
				"b",
				"c",
				"d",
			},
			pathInfo: "test",
			expected: []string{
				"b",
				"c",
			},
			errExpected: false,
		},
		{
			name: "subset",
			a: []string{
				"a",
				"b",
				"c",
			},
			b: []string{
				"b",
				"c",
			},
			pathInfo: "test",
			expected: []string{
				"b",
				"c",
			},
			errExpected: false,
		},
		{
			name: "only one left",
			a: []string{
				"a",
				"b",
				"c",
			},
			b: []string{
				"b",
				"d",
			},
			pathInfo:    "test",
			expected:    []string{"b"},
			errExpected: false,
		},
	}
	op := policyOperatorOneOf
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				merged, err := op.Merge(test.a, test.b, test.pathInfo)
				if err != nil {
					if test.errExpected {
						return
					}
					t.Errorf("did not expect error, but did not verify correctly")
				} else if test.errExpected {
					t.Errorf("expected error, but verified correctly")
				}
				if !utils.SliceEqual(test.expected, merged) {
					t.Errorf("expected merged object to be '%+q', but got '%+q' instead", test.expected, merged)
				}
			},
		)
	}
}

func TestPolicyOperatorOneOfApply(t *testing.T) {
	tests := []struct {
		name        string
		value       any
		policyValue any
		pathInfo    string
		expected    any
		errExpected bool
	}{
		{
			name:        "both nil",
			value:       nil,
			policyValue: nil,
			pathInfo:    "test",
			expected:    nil,
			errExpected: false,
		},
		{
			name:        "policy nil",
			value:       "value",
			policyValue: nil,
			pathInfo:    "test",
			expected:    "value",
			errExpected: false,
		},
		{
			name:  "value nil",
			value: nil,
			policyValue: []string{
				"a",
				"b",
			},
			pathInfo:    "test",
			errExpected: true,
		},
		{
			name:  "one of",
			value: "value",
			policyValue: []string{
				"one",
				"of",
				"value",
			},
			pathInfo:    "test",
			expected:    "value",
			errExpected: false,
		},
		{
			name:  "not one of",
			value: "other",
			policyValue: []string{
				"one",
				"of",
				"value",
			},
			pathInfo:    "test",
			errExpected: true,
		},
		{
			name: "slice as value",
			value: []string{
				"one",
				"of",
				"value",
			},
			policyValue: []string{
				"one",
				"of",
				"value",
			},
			pathInfo:    "test",
			errExpected: true,
		},
	}
	op := policyOperatorOneOf
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				result, err := op.Apply(test.value, test.policyValue, test.pathInfo)
				if err != nil {
					if test.errExpected {
						return
					}
					t.Errorf("did not expect error, but did not verify correctly")
				} else if test.errExpected {
					t.Errorf("expected error, but verified correctly")
				}
				if !utils.SliceEqual(test.expected, result) {
					t.Errorf("expected resulting object to be '%+q', but got '%+q' instead", test.expected, result)
				}
			},
		)
	}
}

func TestPolicyOperatorSupersetOfMerge(t *testing.T) {
	tests := []struct {
		name        string
		a           any
		b           any
		pathInfo    string
		expected    any
		errExpected bool
	}{
		{
			name:        "both nil",
			a:           nil,
			b:           nil,
			pathInfo:    "test",
			expected:    nil,
			errExpected: false,
		},
		{
			name: "a nil",
			a:    nil,
			b: []string{
				"a",
				"b",
			},
			pathInfo: "test",
			expected: []string{
				"a",
				"b",
			},
			errExpected: false,
		},
		{
			name: "b nil",
			a: []string{
				"a",
				"b",
			},
			b:        nil,
			pathInfo: "test",
			expected: []string{
				"a",
				"b",
			},
			errExpected: false,
		},
		{
			name: "a empty",
			a:    []string{},
			b: []string{
				"a",
				"b",
			},
			pathInfo: "test",
			expected: []string{
				"a",
				"b",
			},
			errExpected: false,
		},
		{
			name: "b empty",
			a: []string{
				"a",
				"b",
			},
			b:        []string{},
			pathInfo: "test",
			expected: []string{
				"a",
				"b",
			},
			errExpected: false,
		},
		{
			name: "equal",
			a: []string{
				"a",
				"b",
			},
			b: []string{
				"a",
				"b",
			},
			pathInfo: "test",
			expected: []string{
				"a",
				"b",
			},
			errExpected: false,
		},
		{
			name: "distinct",
			a: []string{
				"a",
				"b",
			},
			b: []string{
				"c",
				"d",
			},
			pathInfo: "test",
			expected: []string{
				"a",
				"b",
				"c",
				"d",
			},
			errExpected: false,
		},
		{
			name: "mixed",
			a: []string{
				"a",
				"b",
			},
			b: []string{
				"b",
				"c",
			},
			pathInfo: "test",
			expected: []string{
				"a",
				"b",
				"c",
			},
			errExpected: false,
		},
	}
	op := policyOperatorSupersetOf
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				merged, err := op.Merge(test.a, test.b, test.pathInfo)
				if err != nil {
					if test.errExpected {
						return
					}
					t.Errorf("did not expect error, but did not verify correctly")
				} else if test.errExpected {
					t.Errorf("expected error, but verified correctly")
				}
				if !utils.SliceEqual(test.expected, merged) {
					t.Errorf("expected merged object to be '%+q', but got '%+q' instead", test.expected, merged)
				}
			},
		)
	}
}

func TestPolicyOperatorSupersetOfApply(t *testing.T) {
	tests := []struct {
		name        string
		value       any
		policyValue any
		pathInfo    string
		expected    any
		errExpected bool
	}{
		{
			name:        "both nil",
			value:       nil,
			policyValue: nil,
			pathInfo:    "test",
			expected:    nil,
			errExpected: false,
		},
		{
			name: "policy nil",
			value: []string{
				"a",
				"b",
			},
			policyValue: nil,
			pathInfo:    "test",
			expected: []string{
				"a",
				"b",
			},
			errExpected: false,
		},
		{
			name: "policy empty",
			value: []string{
				"a",
				"b",
			},
			policyValue: []string{},
			pathInfo:    "test",
			expected: []string{
				"a",
				"b",
			},
			errExpected: false,
		},
		{
			name:        "value nil",
			value:       nil,
			policyValue: []string{"a"},
			pathInfo:    "test",
			errExpected: true,
		},
		{
			name:        "value empty",
			value:       []string{},
			policyValue: []string{"a"},
			pathInfo:    "test",
			errExpected: true,
		},
		{
			name: "equal",
			value: []string{
				"a",
				"b",
			},
			policyValue: []string{
				"a",
				"b",
			},
			pathInfo: "test",
			expected: []string{
				"a",
				"b",
			},
			errExpected: false,
		},
		{
			name: "superset",
			value: []string{
				"a",
				"b",
			},
			policyValue: []string{"a"},
			pathInfo:    "test",
			expected: []string{
				"a",
				"b",
			},
			errExpected: false,
		},
		{
			name: "no superset",
			value: []string{
				"a",
				"b",
			},
			policyValue: []string{
				"a",
				"c",
			},
			pathInfo:    "test",
			errExpected: true,
		},
	}
	op := policyOperatorSupersetOf
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				result, err := op.Apply(test.value, test.policyValue, test.pathInfo)
				if err != nil {
					if test.errExpected {
						return
					}
					t.Errorf("did not expect error, but did not verify correctly")
				} else if test.errExpected {
					t.Errorf("expected error, but verified correctly")
				}
				if !utils.SliceEqual(test.expected, result) {
					t.Errorf("expected resulting object to be '%+q', but got '%+q' instead", test.expected, result)
				}
			},
		)
	}
}

func TestPolicyOperatorValueMerge(t *testing.T) {
	tests := []struct {
		name        string
		a           any
		b           any
		pathInfo    string
		expected    any
		errExpected bool
	}{
		{
			name:        "both nil",
			a:           nil,
			b:           nil,
			pathInfo:    "test",
			expected:    nil,
			errExpected: false,
		},
		{
			name:        "a nil",
			a:           nil,
			b:           "value",
			pathInfo:    "test",
			expected:    "value",
			errExpected: false,
		},
		{
			name:        "b nil",
			a:           "value",
			b:           nil,
			pathInfo:    "test",
			expected:    "value",
			errExpected: false,
		},
		{
			name:        "equal string",
			a:           "value",
			b:           "value",
			pathInfo:    "test",
			expected:    "value",
			errExpected: false,
		},
		{
			name:        "different string",
			a:           "value",
			b:           "value2",
			pathInfo:    "test",
			errExpected: true,
		},
		{
			name: "equal slices",
			a: []string{
				"a",
				"b",
			},
			b: []string{
				"a",
				"b",
			},
			pathInfo: "test",
			expected: []string{
				"a",
				"b",
			},
			errExpected: false,
		},
		{
			name: "equal slices wrong order",
			a: []string{
				"a",
				"b",
			},
			b: []string{
				"b",
				"a",
			},
			pathInfo: "test",
			expected: []string{
				"a",
				"b",
			},
			errExpected: false,
		},
		{
			name: "different slices",
			a: []string{
				"a",
				"b",
				"c",
			},
			b: []string{
				"b",
				"a",
			},
			pathInfo:    "test",
			errExpected: true,
		},
	}
	op := policyOperatorValue
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				merged, err := op.Merge(test.a, test.b, test.pathInfo)
				if err != nil {
					if test.errExpected {
						return
					}
					t.Errorf("did not expect error, but did not verify correctly")
				} else if test.errExpected {
					t.Errorf("expected error, but verified correctly")
				}
				if !utils.SliceEqual(test.expected, merged) {
					t.Errorf("expected merged object to be '%+q', but got '%+q' instead", test.expected, merged)
				}
			},
		)
	}
}

func TestPolicyOperatorValueApply(t *testing.T) {
	tests := []struct {
		name        string
		value       any
		policyValue any
		pathInfo    string
		expected    any
		errExpected bool
	}{
		{
			name:        "both nil",
			value:       nil,
			policyValue: nil,
			pathInfo:    "test",
			expected:    nil,
			errExpected: false,
		},
		{
			name:        "policy nil",
			value:       "value",
			policyValue: nil,
			pathInfo:    "test",
			expected:    "value",
			errExpected: false,
		},
		{
			name:        "policy string",
			value:       "value",
			policyValue: "overwrite",
			pathInfo:    "test",
			expected:    "overwrite",
			errExpected: false,
		},
		{
			name:  "policy slice string",
			value: "value",
			policyValue: []string{
				"overwrite",
				"with",
				"values",
			},
			pathInfo: "test",
			expected: []string{
				"overwrite",
				"with",
				"values",
			},
			errExpected: false,
		},
	}
	op := policyOperatorValue
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				result, err := op.Apply(test.value, test.policyValue, test.pathInfo)
				if err != nil {
					if test.errExpected {
						return
					}
					t.Errorf("did not expect error, but did not verify correctly")
				} else if test.errExpected {
					t.Errorf("expected error, but verified correctly")
				}
				if !utils.SliceEqual(test.expected, result) {
					t.Errorf("expected resulting object to be '%+q', but got '%+q' instead", test.expected, result)
				}
			},
		)
	}
}

func TestPolicyOperatorDefaultMerge(t *testing.T) {
	tests := []struct {
		name        string
		a           any
		b           any
		pathInfo    string
		expected    any
		errExpected bool
	}{
		{
			name:        "both nil",
			a:           nil,
			b:           nil,
			pathInfo:    "test",
			expected:    nil,
			errExpected: false,
		},
		{
			name:        "a nil",
			a:           nil,
			b:           "value",
			pathInfo:    "test",
			expected:    "value",
			errExpected: false,
		},
		{
			name:        "b nil",
			a:           "value",
			b:           nil,
			pathInfo:    "test",
			expected:    "value",
			errExpected: false,
		},
		{
			name:        "equal string",
			a:           "value",
			b:           "value",
			pathInfo:    "test",
			expected:    "value",
			errExpected: false,
		},
		{
			name:        "different string",
			a:           "value",
			b:           "value2",
			pathInfo:    "test",
			errExpected: true,
		},
		{
			name: "equal slices",
			a: []string{
				"a",
				"b",
			},
			b: []string{
				"a",
				"b",
			},
			pathInfo: "test",
			expected: []string{
				"a",
				"b",
			},
			errExpected: false,
		},
		{
			name: "equal slices wrong order",
			a: []string{
				"a",
				"b",
			},
			b: []string{
				"b",
				"a",
			},
			pathInfo: "test",
			expected: []string{
				"a",
				"b",
			},
			errExpected: false,
		},
		{
			name: "different slices",
			a: []string{
				"a",
				"b",
				"c",
			},
			b: []string{
				"b",
				"a",
			},
			pathInfo:    "test",
			errExpected: true,
		},
	}
	op := policyOperatorDefault
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				merged, err := op.Merge(test.a, test.b, test.pathInfo)
				if err != nil {
					if test.errExpected {
						return
					}
					t.Errorf("did not expect error, but did not verify correctly")
				} else if test.errExpected {
					t.Errorf("expected error, but verified correctly")
				}
				if !utils.SliceEqual(test.expected, merged) {
					t.Errorf("expected merged object to be '%+q', but got '%+q' instead", test.expected, merged)
				}
			},
		)
	}
}

func TestPolicyOperatorDefaultApply(t *testing.T) {
	tests := []struct {
		name        string
		value       any
		policyValue any
		pathInfo    string
		expected    any
		errExpected bool
	}{
		{
			name:        "both nil",
			value:       nil,
			policyValue: nil,
			pathInfo:    "test",
			expected:    nil,
			errExpected: false,
		},
		{
			name:        "policy nil",
			value:       "value",
			policyValue: nil,
			pathInfo:    "test",
			expected:    "value",
			errExpected: false,
		},
		{
			name:        "value nil",
			value:       nil,
			policyValue: "value",
			pathInfo:    "test",
			expected:    "value",
			errExpected: false,
		},
		{
			name:        "value empty string",
			value:       "",
			policyValue: "value",
			pathInfo:    "test",
			expected:    "value",
			errExpected: false,
		},
		{
			name:        "value empty struct",
			value:       struct{}{},
			policyValue: "value",
			pathInfo:    "test",
			expected:    "value",
			errExpected: false,
		},
		{
			name:        "policy string",
			value:       "value",
			policyValue: "default",
			pathInfo:    "test",
			expected:    "value",
			errExpected: false,
		},
		{
			name:  "policy slice string",
			value: "value",
			policyValue: []string{
				"default",
				"with",
				"values",
			},
			pathInfo:    "test",
			expected:    "value",
			errExpected: false,
		},
	}
	op := policyOperatorDefault
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				result, err := op.Apply(test.value, test.policyValue, test.pathInfo)
				if err != nil {
					if test.errExpected {
						return
					}
					t.Errorf("did not expect error, but did not verify correctly")
				} else if test.errExpected {
					t.Errorf("expected error, but verified correctly")
				}
				if !utils.SliceEqual(test.expected, result) {
					t.Errorf("expected resulting object to be '%+q', but got '%+q' instead", test.expected, result)
				}
			},
		)
	}
}

func TestPolicyOperatorEssentialMerge(t *testing.T) {
	tests := []struct {
		name        string
		a           any
		b           any
		pathInfo    string
		expected    any
		errExpected bool
	}{
		{
			name:        "both nil",
			a:           nil,
			b:           nil,
			pathInfo:    "test",
			expected:    false,
			errExpected: false,
		},
		{
			name:        "nil + false",
			a:           nil,
			b:           false,
			pathInfo:    "test",
			expected:    false,
			errExpected: false,
		},
		{
			name:        "false + nil",
			a:           false,
			b:           nil,
			pathInfo:    "test",
			expected:    false,
			errExpected: false,
		},
		{
			name:        "nil + true",
			a:           nil,
			b:           true,
			pathInfo:    "test",
			expected:    true,
			errExpected: false,
		},
		{
			name:        "true + nil",
			a:           true,
			b:           nil,
			pathInfo:    "test",
			expected:    true,
			errExpected: false,
		},
		{
			name:        "false + true",
			a:           false,
			b:           true,
			pathInfo:    "test",
			expected:    true,
			errExpected: false,
		},
		{
			name:        "true + false",
			a:           true,
			b:           false,
			pathInfo:    "test",
			expected:    true,
			errExpected: false,
		},
		{
			name:        "true + true",
			a:           true,
			b:           true,
			pathInfo:    "test",
			expected:    true,
			errExpected: false,
		},
		{
			name:        "false + false",
			a:           false,
			b:           false,
			pathInfo:    "test",
			expected:    false,
			errExpected: false,
		},
	}
	op := policyOperatorEssential
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				merged, err := op.Merge(test.a, test.b, test.pathInfo)
				if err != nil {
					if test.errExpected {
						return
					}
					t.Errorf("did not expect error, but did not verify correctly")
				} else if test.errExpected {
					t.Errorf("expected error, but verified correctly")
				}
				if !utils.SliceEqual(test.expected, merged) {
					t.Errorf("expected merged object to be '%+q', but got '%+q' instead", test.expected, merged)
				}
			},
		)
	}
}

func TestPolicyOperatorEssentialApply(t *testing.T) {
	tests := []struct {
		name        string
		value       any
		policyValue any
		pathInfo    string
		expected    any
		errExpected bool
	}{
		{
			name:        "both nil",
			value:       nil,
			policyValue: nil,
			pathInfo:    "test",
			expected:    nil,
			errExpected: false,
		},
		{
			name:        "value nil + false",
			value:       nil,
			policyValue: false,
			pathInfo:    "test",
			expected:    nil,
			errExpected: false,
		},
		{
			name:        "value nil + true",
			value:       nil,
			policyValue: true,
			pathInfo:    "test",
			expected:    nil,
			errExpected: true,
		},
		{
			name:        "value empty string + true",
			value:       "",
			policyValue: true,
			pathInfo:    "test",
			errExpected: true,
		},
		{
			name:        "value empty struct + true",
			value:       struct{}{},
			policyValue: true,
			pathInfo:    "test",
			errExpected: true,
		},
		{
			name:        "value string + true",
			value:       "value",
			policyValue: true,
			pathInfo:    "test",
			expected:    "value",
			errExpected: false,
		},
		{
			name:        "value empty string + false",
			value:       "",
			policyValue: false,
			pathInfo:    "test",
			expected:    "",
			errExpected: false,
		},
		{
			name:        "value empty struct + false",
			value:       struct{}{},
			policyValue: false,
			pathInfo:    "test",
			expected:    struct{}{},
			errExpected: false,
		},
		{
			name:        "value string + false",
			value:       "value",
			policyValue: false,
			pathInfo:    "test",
			expected:    "value",
			errExpected: false,
		},
	}
	op := policyOperatorEssential
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				result, err := op.Apply(test.value, test.policyValue, test.pathInfo)
				if err != nil {
					if test.errExpected {
						return
					}
					t.Errorf("did not expect error, but did not verify correctly")
				} else if test.errExpected {
					t.Errorf("expected error, but verified correctly")
				}
				if !utils.SliceEqual(test.expected, result) {
					t.Errorf("expected resulting object to be '%+q', but got '%+q' instead", test.expected, result)
				}
			},
		)
	}
}
