package utils

import (
	"testing"
)

func TestCompareEntityIDs(t *testing.T) {
	tests := []struct {
		name string
		a    string
		b    string
		want bool
	}{
		{
			name: "Equal without trailing slash",
			a:    "https://test.example.com",
			b:    "https://test.example.com",
			want: true,
		},
		{
			name: "Equal with trailing slash",
			a:    "https://test.example.com/",
			b:    "https://test.example.com/",
			want: true,
		},
		{
			name: "Only a with trailing slash",
			a:    "https://test.example.com/",
			b:    "https://test.example.com",
			want: true,
		},
		{
			name: "Only b with trailing slash",
			a:    "https://test.example.com",
			b:    "https://test.example.com/",
			want: true,
		},
		{
			name: "Different one char",
			a:    "https://test.example.co",
			b:    "https://test.example.com",
			want: false,
		},
		{
			name: "difference but same length",
			a:    "https://foo.example.com",
			b:    "https://bar.example.com",
			want: false,
		},
		{
			name: "difference with difference length",
			a:    "https://foo.example.com",
			b:    "https://example.com",
			want: false,
		},
	}
	for _, test := range tests {
		t.Run(
			test.name, func(t *testing.T) {
				same := CompareEntityIDs(test.a, test.b)
				if same != test.want {
					t.Errorf("CompareEntityIDs(%v, %v) = %v, want %v", test.a, test.b, same, test.want)
				}
			},
		)
	}
}
