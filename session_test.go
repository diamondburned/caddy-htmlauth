package htmlauth

import (
	"testing"
)

func TestSessionToken(t *testing.T) {
	t.Log("token:", genSessionToken())
}

func BenchmarkSessionToken(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = genSessionToken()
	}
}
