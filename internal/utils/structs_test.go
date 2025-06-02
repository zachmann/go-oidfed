package utils

import (
	"reflect"
	"testing"
)

func TestNilAllExceptByTag(t *testing.T) {
	type TaggedStruct struct {
		HasTag    *struct{} `json:"has_tag"`
		OtherTag  *struct{} `json:"other_tag"`
		NoTag     *struct{}
		OmitEmpty *struct{} `json:"omit_empty,omitempty"`
		YAMLTag   *struct{} `yaml:"yaml_tag"`
		Extra     map[string]any
	}

	tests := []struct {
		name     string
		input    TaggedStruct
		jsonTags []string
		expected TaggedStruct
	}{
		{
			name: "no extra",
			input: TaggedStruct{
				HasTag:    &struct{}{},
				OtherTag:  &struct{}{},
				NoTag:     &struct{}{},
				OmitEmpty: &struct{}{},
				YAMLTag:   &struct{}{},
				Extra:     nil,
			},
			jsonTags: []string{
				"has_tag", "NoTag", "omit_empty", "yaml_tag",
			},
			expected: TaggedStruct{
				HasTag:    &struct{}{},
				OtherTag:  nil,
				NoTag:     &struct{}{},
				OmitEmpty: &struct{}{},
				YAMLTag:   nil,
				Extra:     nil,
			},
		},
		{
			name: "with extra",
			input: TaggedStruct{
				HasTag: &struct{}{},
				Extra: map[string]any{
					"key1": &struct{}{},
					"key2": &struct{}{},
				},
			},
			jsonTags: []string{"key1"},
			expected: TaggedStruct{
				Extra: map[string]any{"key1": &struct{}{}},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			NilAllExceptByTag(&test.input, test.jsonTags)
			if !reflect.DeepEqual(test.input, test.expected) {
				t.Errorf("NilAllExceptByTag: sanitized struct has unexpected value %+v", test.input)
			}
		})
	}
}

func TestNilAllExceptByTagExtraWrongType(t *testing.T) {
	type ExtraWrongType struct {
		Extra map[string]int
	}

	input := ExtraWrongType{Extra: map[string]int{"key": 1}}
	NilAllExceptByTag(&input, []string{"key"})

	if !reflect.DeepEqual(input, ExtraWrongType{Extra: nil}) {
		t.Errorf("NilAllExceptByTag: sanitized struct has unexpected Extra value %+v", input)
	}
}
