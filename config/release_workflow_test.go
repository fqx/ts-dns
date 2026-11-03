package config

import (
	"go/constant"
	"go/token"
	"go/types"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// Evaluate the actual publish condition for representative GitHub event contexts.
// The gate uses constant comparisons, &&, and startsWith, so Go's constant
// evaluator can evaluate it after substituting the context and startsWith call.
func TestReleasePublishGate(t *testing.T) {
	workflow, err := os.ReadFile("../.github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	match := regexp.MustCompile(`(?m)^  publish:\n    if: (.+)$`).FindSubmatch(workflow)
	if match == nil {
		t.Fatal("publish job must have an explicit condition")
	}
	condition := string(match[1])
	prefixCall := regexp.MustCompile(`startsWith\(github\.ref,\s*'([^']+)'\)`)
	literal := regexp.MustCompile(`'([^']*)'`)
	for _, tc := range []struct {
		event, ref string
		publish    bool
	}{
		{"push", "refs/tags/v1.2.3", true},
		{"workflow_dispatch", "refs/tags/v1.2.3", false},
		{"workflow_dispatch", "refs/heads/master", false},
		{"push", "refs/heads/master", false},
		{"push", "refs/tags/test-build", false},
		{"pull_request", "refs/tags/v1.2.3", false},
	} {
		t.Run(tc.event+"/"+tc.ref, func(t *testing.T) {
			expr := prefixCall.ReplaceAllStringFunc(condition, func(call string) string {
				prefix := prefixCall.FindStringSubmatch(call)[1]
				return strconv.FormatBool(strings.HasPrefix(tc.ref, prefix))
			})
			expr = literal.ReplaceAllStringFunc(expr, func(s string) string {
				return strconv.Quote(s[1 : len(s)-1])
			})
			expr = strings.ReplaceAll(expr, "github.event_name", strconv.Quote(tc.event))
			value, err := types.Eval(token.NewFileSet(), nil, token.NoPos, expr)
			if err != nil {
				t.Fatalf("cannot evaluate publish condition %q: %v", condition, err)
			}
			if value.Value == nil || value.Value.Kind() != constant.Bool {
				t.Fatal("publish condition must evaluate to a boolean")
			}
			if got := constant.BoolVal(value.Value); got != tc.publish {
				t.Fatalf("publish = %t, want %t (condition: %s)", got, tc.publish, condition)
			}
		})
	}
}
