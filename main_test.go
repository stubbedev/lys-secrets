package main

import "testing"

func TestGreet(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "simple", in: "world", want: "hello, world"},
		{name: "other", in: "gopher", want: "hello, gopher"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := greet(tc.in); got != tc.want {
				t.Errorf("greet(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
