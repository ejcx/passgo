package generate

import (
	"testing"
	"unicode/utf8"
)

var generateTests = []struct {
	n        int // input
	expected int // expected result
}{
	{0, 24},
	{-1, 24},
	{5, 5},
	{10, 10},
	{1 << 18, 24},
	{1<<32 - 1, 24},
}

func TestGenerate(t *testing.T) {
	for _, tt := range generateTests {
		actual := Generate(tt.n)
		actual_length := utf8.RuneCountInString(actual)

		if actual_length < tt.expected {
			t.Errorf("Generate(%d): expected >= %d, actual %d", tt.n, tt.expected, actual_length)
		}
	}
}
