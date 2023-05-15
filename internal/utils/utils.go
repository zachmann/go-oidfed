package utils

import (
	"github.com/fatih/structs"
	"reflect"
	"strings"
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
