package nuclei

import (
	"testing"
)

// callSeq returns a call function recording the sequence of n's it was
// invoked with, plus a lookup returning result[n] (default true) — lets a
// test assert both the outcome and which requests were actually reached
// (short-circuit behavior).
func callSeq(results map[int]bool) (call func(n int) (bool, error), seq *[]int) {
	var s []int
	seq = &s
	call = func(n int) (bool, error) {
		s = append(s, n)
		if r, ok := results[n]; ok {
			return r, nil
		}
		return true, nil
	}
	return call, seq
}

func TestParseFlow_RealCorpusShapes(t *testing.T) {
	tests := []struct {
		name     string
		expr     string
		wantMaxN int
	}{
		{"single and", "http(1) && http(2)", 2},
		{"single or", "http(1) || http(2)", 2},
		{"three-way and", "http(1) && http(2) && http(3)", 3},
		{"mixed and/or with parens", "http(1) && (http(2) || http(3))", 3},
		{"whitespace-insensitive", "http( 1 )&&http(2)", 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ast, maxN, err := parseFlow(tt.expr)
			if err != nil {
				t.Fatalf("parseFlow(%q) returned error: %v", tt.expr, err)
			}
			if maxN != tt.wantMaxN {
				t.Errorf("parseFlow(%q) maxN = %d, want %d", tt.expr, maxN, tt.wantMaxN)
			}
			if ast == nil {
				t.Errorf("parseFlow(%q) returned nil AST", tt.expr)
			}
		})
	}
}

func TestParseFlow_ShortCircuit(t *testing.T) {
	tests := []struct {
		name    string
		expr    string
		results map[int]bool
		want    bool
		wantSeq []int
	}{
		{"and short-circuits on false", "http(1) && http(2)", map[int]bool{1: false}, false, []int{1}},
		{"and runs both when true", "http(1) && http(2)", map[int]bool{1: true, 2: true}, true, []int{1, 2}},
		{"or short-circuits on true", "http(1) || http(2)", map[int]bool{1: true}, true, []int{1}},
		{"or runs both when false", "http(1) || http(2)", map[int]bool{1: false, 2: false}, false, []int{1, 2}},
		{"mixed: right branch skipped when left of || true", "http(1) && (http(2) || http(3))", map[int]bool{1: true, 2: true}, true, []int{1, 2}},
		{"mixed: right branch runs when left of || false", "http(1) && (http(2) || http(3))", map[int]bool{1: true, 2: false, 3: true}, true, []int{1, 2, 3}},
		{"mixed: nothing past http(1) when it's false", "http(1) && (http(2) || http(3))", map[int]bool{1: false}, false, []int{1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ast, _, err := parseFlow(tt.expr)
			if err != nil {
				t.Fatalf("parseFlow(%q) returned error: %v", tt.expr, err)
			}
			call, seq := callSeq(tt.results)
			got, err := ast.eval(call)
			if err != nil {
				t.Fatalf("eval returned error: %v", err)
			}
			if got != tt.want {
				t.Errorf("eval(%q) = %v, want %v", tt.expr, got, tt.want)
			}
			if len(*seq) != len(tt.wantSeq) {
				t.Fatalf("eval(%q) call sequence = %v, want %v", tt.expr, *seq, tt.wantSeq)
			}
			for i, n := range tt.wantSeq {
				if (*seq)[i] != n {
					t.Errorf("eval(%q) call sequence = %v, want %v", tt.expr, *seq, tt.wantSeq)
					break
				}
			}
		})
	}
}

func TestParseFlow_RejectsUnsupportedConstructs(t *testing.T) {
	tests := []string{
		"",
		"javascript()",
		"http()",
		"http(0)",
		"http(1) &&",
		"http(1) && http(2))",
		"(http(1)",
		"http(1) && set(x, 1)",
		"for (i = 0; i < 3; i++) { http(1) }",
	}
	for _, expr := range tests {
		t.Run(expr, func(t *testing.T) {
			if _, _, err := parseFlow(expr); err == nil {
				t.Errorf("parseFlow(%q) expected an error, got none", expr)
			}
		})
	}
}
