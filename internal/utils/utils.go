package utils

import (
	"reflect"
	"strings"

	"github.com/fatih/structs"
	"tideland.dev/go/slices"
)

// Equal compares multiple comparable values for equality
func Equal[C comparable](v C, values ...C) bool {
	for _, vv := range values {
		if v != vv {
			return false
		}
	}
	return true
}

// IsMap uses reflection to check if an interface{} is a map
func IsMap(v interface{}) bool {
	return reflect.TypeOf(v).Kind() == reflect.Map
}

// MapKeys returns the keys of the map m.
// The keys will be an indeterminate order.
func MapKeys[M ~map[K]V, K comparable, V any](m M) []K {
	r := make([]K, 0, len(m))
	for k := range m {
		r = append(r, k)
	}
	return r
}

// FieldTagNames returns a slice of the tag names for a []*structs.Field and the given tag
func FieldTagNames(fields []*structs.Field, tag string) (names []string) {
	for _, f := range fields {
		if f == nil {
			continue
		}
		t := f.Tag(tag)
		if i := strings.IndexRune(t, ','); i > 0 {
			t = t[:i]
		}
		if t != "" && t != "-" {
			names = append(names, t)
		}
	}
	return
}

// FirstNonEmpty is a utility function returning the first of the passed values that is not empty/zero
func FirstNonEmpty[C comparable](possibleValues ...C) C {
	var nullValue C
	for _, v := range possibleValues {
		if v != nullValue {
			return v
		}
	}
	return nullValue
}

// MergeMaps merges two or more maps into on; overwrite determines if values are overwritten if already set or not
func MergeMaps(overwrite bool, mm ...map[string]any) map[string]any {
	if !overwrite {
		return MergeMaps(true, slices.Reverse(mm)...)
	}
	all := make(map[string]any)
	for _, m := range mm {
		for k, v := range m {
			all[k] = v
		}
	}
	return all
}

// NewInt returns a *int
func NewInt(i int) *int {
	return &i
}

func CompareEntityIDs(a, b string) bool {
	aLen := len(a)
	bLen := len(b)
	lenDiff := bLen - aLen
	if lenDiff > 1 || lenDiff < -1 {
		return false
	}
	if a[aLen-1] != '/' {
		a += "/"
	}
	if b[bLen-1] != '/' {
		b += "/"
	}
	return a == b
}

func TheOtherEntityIDComparisonOption(id string) string {
	l := len(id)
	if l < 2 {
		return id
	}
	if id[l-1] == '/' {
		return id[:l-2]
	}
	return id + "/"
}
