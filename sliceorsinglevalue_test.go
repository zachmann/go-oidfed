package oidfed

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

func TestSliceOrSingleValue_Marshal(t *testing.T) {
	tests := []struct {
		name string
		v    SliceOrSingleValue[string]
		json []byte
	}{
		{
			name: "nil",
			v:    nil,
			json: []byte("null"),
		},
		{
			name: "single value",
			v:    SliceOrSingleValue[string]{"value"},
			json: []byte("\"value\""),
		},
		{
			name: "multiple values",
			v: SliceOrSingleValue[string]{
				"value",
				"and",
				"more",
			},
			json: []byte("[\"value\",\"and\",\"more\"]"),
		},
	}
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				j, err := json.Marshal(test.v)
				if err != nil {
					t.Error(err)
				}
				if !bytes.Equal(j, test.json) {
					t.Errorf("marshalled json not as expected; expected: '%s', got '%s'", j, test.json)
				}
			},
		)
	}
}

func TestSliceOrSingleValue_Unmarshal(t *testing.T) {
	tests := []struct {
		name     string
		json     []byte
		expected SliceOrSingleValue[string]
	}{
		{
			name:     "single value",
			json:     []byte("\"value\""),
			expected: SliceOrSingleValue[string]{"value"},
		},
		{
			name: "multiple values",
			json: []byte("[\"value\",\"and\",\"more\"]"),
			expected: SliceOrSingleValue[string]{
				"value",
				"and",
				"more",
			},
		},
	}
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				var v SliceOrSingleValue[string]
				if err := json.Unmarshal(test.json, &v); err != nil {
					t.Error(err)
				}
				if !reflect.DeepEqual(v, test.expected) {
					t.Errorf("unmarshalled value not as expected; expected: '%+v', got '%+v'", test.expected, v)
				}
			},
		)
	}
}
