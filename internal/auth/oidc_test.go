package auth

import "testing"

func TestOIDCEmailVerified(t *testing.T) {
	cases := []struct {
		in   any
		want bool
	}{
		{nil, true},
		{true, true},
		{false, false},
		{"true", true},
		{"false", false},
		{float64(1), true},
		{float64(0), false},
	}
	for _, tc := range cases {
		if got := oidcEmailVerified(tc.in); got != tc.want {
			t.Fatalf("oidcEmailVerified(%v)=%v want %v", tc.in, got, tc.want)
		}
	}
}
