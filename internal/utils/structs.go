package utils

import (
	"reflect"
	"strings"
)

// NilAllButOneByTag sets all fields of a struct to their zero values except for the field with the specified JSON tag.
func NilAllButOneByTag(v interface{}, jsonTag string) {
	val := reflect.ValueOf(v).Elem()
	typ := val.Type()

	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		fieldType := typ.Field(i)
		tag := fieldType.Tag.Get("json")

		// Handle the case where the tag includes ",omitempty" or other options
		tagParts := strings.Split(tag, ",")
		baseTag := tagParts[0]

		if baseTag == "" {
			// If no json tag is present, use the field name as the tag
			baseTag = fieldType.Name
		}

		// If this is not the field to keep, set it to its zero value
		if baseTag != jsonTag {
			field.Set(reflect.Zero(field.Type()))
		}
	}

}
