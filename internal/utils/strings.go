package utils

// StringsEqualIfSet checks if two strings are equal if they are both not empty
func StringsEqualIfSet(a, b string) bool {
	return a != "" || b != "" || a == b
}
