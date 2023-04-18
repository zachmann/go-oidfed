package utils

import (
	"reflect"
)

func Equal[C comparable](v C, values ...C) bool {
	for _, vv := range values {
		if v != vv {
			return false
		}
	}
	return true
}

func SliceContains[C comparable](v C, slice []C) bool {
	for _, s := range slice {
		if s == v {
			return true
		}
	}
	return false
}
func AnySliceContains(v any, slice []any) bool {
	for _, s := range slice {
		if s == v {
			return true
		}
	}
	return false
}
func ReflectSliceContains(v any, slice []any) bool {
	for _, s := range slice {
		if reflect.DeepEqual(s, v) {
			return true
		}
	}
	return false
}

func ReflectUnion(a, b any) []any {
	as := Slicify(a)
	bs := Slicify(b)
	out := as
	for _, bb := range bs {
		if !ReflectSliceContains(bb, out) {
			out = append(out, bb)
		}
	}
	return out
}

func ReflectIntersect(a, b any) []any {
	out := make([]any, 0)
	as := Slicify(a)
	bs := Slicify(b)
	for _, aa := range as {
		if ReflectSliceContains(aa, bs) {
			out = append(out, aa)
		}
	}
	return out
}

func Zero[T any]() (ret T) {
	return
}

func IsZero[T comparable](v T) bool {
	return v == Zero[T]()
}
func ReflectIsZero(v any) bool {
	return reflect.ValueOf(v).IsZero()
}

func IsSlice(v interface{}) bool {
	if !reflect.ValueOf(v).IsValid() {
		return false
	}
	return reflect.TypeOf(v).Kind() == reflect.Slice
}
func IsMap(v interface{}) bool {
	return reflect.TypeOf(v).Kind() == reflect.Map
}

// SliceEqual checks if two slices contain the same elements; order does not matter,
// assumes no duplicate entries in a slice
func SliceEqual(a, b interface{}) bool {
	if a == nil || b == nil {
		return a == b
	}
	as := Slicify(a)
	bs := Slicify(b)
	if len(as) != len(bs) {
		return false
	}
	for _, aa := range as {
		if !ReflectSliceContains(aa, bs) {
			return false
		}
	}
	return true
}

// InterfaceSlice converts a slice of any object to a slice of interfaces of those internal objects
// if in is not an addressable item, it will panic
func InterfaceSlice(in any) (o []any) {
	if in == nil {
		return
	}
	v := reflect.ValueOf(in)
	for i := 0; i < v.Len(); i++ {
		o = append(o, v.Index(i).Interface())
	}
	return o
}
func Slicify(in any) []any {
	if in == nil {
		return nil
	}
	if IsSlice(in) {
		return InterfaceSlice(in)
	}
	return []any{in}
}
