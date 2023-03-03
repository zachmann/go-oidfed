package pkg

import (
	"encoding/json"
)

// SliceOrSingleValue is a type that supports (un-)marshaling
// (json) of a slice where a single value might not be expressed as a slice
type SliceOrSingleValue[T any] []T

// UnmarshalJSON implements the json.Unmarshaler interface
func (v *SliceOrSingleValue[T]) UnmarshalJSON(data []byte) error {
	var t T
	if json.Unmarshal(data, &t) == nil {
		*v = []T{t}
		return nil
	}
	var tSlice []T
	if err := json.Unmarshal(data, &tSlice); err != nil {
		return err
	}
	*v = tSlice
	return nil
}

// MarshalJSON implements the json.Marshaler interface
func (v SliceOrSingleValue[T]) MarshalJSON() ([]byte, error) {
	if len(v) == 1 {
		return json.Marshal(v[0])
	}
	return json.Marshal([]T(v))
}
