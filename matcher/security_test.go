package matcher

import "testing"

func TestUntrustedRulesDoNotPanic(t *testing.T) {
	for _, text := range []string{`/^https?:\/\/.*/`, `/^https?:\/\/([\/.*/`, `*[.example.com`, `*+.example.com`, `*?.example.com`} {
		m := NewABPByText(text)
		m.Match("example.com")
	}
}
