package tunnels

import "testing"

func TestParsePortSet(t *testing.T) {
	tests := []struct {
		spec    string
		want    string
		matches []int
		misses  []int
	}{
		{"", "", nil, []int{80, 3000}},
		{"3000", "3000", []int{3000}, []int{2999, 3001}},
		{"8000-9000", "8000-9000", []int{8000, 8500, 9000}, []int{7999, 9001}},
		{"3000,8000-9000", "3000,8000-9000", []int{3000, 8080}, []int{4000}},
		{"9000-8000 ", "", nil, nil}, // reversed range is an error
		{"  3000 , 3001  ", "3000,3001", []int{3000, 3001}, []int{3002}},
		{"5000-5000", "5000", []int{5000}, []int{5001}},
		{"1,65535", "1,65535", []int{1, 65535}, []int{2}},
	}
	for _, tt := range tests {
		got, err := ParsePortSet(tt.spec)
		if tt.want == "" && tt.spec != "" && len(tt.matches) == 0 && tt.misses == nil {
			if err == nil {
				t.Errorf("ParsePortSet(%q) should have failed", tt.spec)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParsePortSet(%q) = %v", tt.spec, err)
			continue
		}
		if got.String() != tt.want {
			t.Errorf("ParsePortSet(%q).String() = %q, want %q", tt.spec, got.String(), tt.want)
		}
		for _, p := range tt.matches {
			if !got.Contains(p) {
				t.Errorf("ParsePortSet(%q) should contain %d", tt.spec, p)
			}
		}
		for _, p := range tt.misses {
			if got.Contains(p) {
				t.Errorf("ParsePortSet(%q) should not contain %d", tt.spec, p)
			}
		}
	}
}

func TestParsePortSetErrors(t *testing.T) {
	for _, spec := range []string{"abc", "0", "65536", "-1", "100-", "-100", "1-2-3", "3000,abc"} {
		if _, err := ParsePortSet(spec); err == nil {
			t.Errorf("ParsePortSet(%q) should have failed", spec)
		}
	}
}

func TestPortSetEmpty(t *testing.T) {
	empty, _ := ParsePortSet("")
	if !empty.Empty() {
		t.Error("an empty spec should produce an empty set")
	}
	full, _ := ParsePortSet("1-65535")
	if full.Empty() {
		t.Error("a populated set should not report empty")
	}
	// An empty set must never match, so that "no --include" means "no filter"
	// rather than "match nothing".
	if empty.Contains(3000) {
		t.Error("an empty set should not contain anything")
	}
}
