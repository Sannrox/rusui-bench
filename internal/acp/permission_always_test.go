package acp

import "testing"

// An allow covers one call. A guest option that persists the grant, named by
// kind or by id, would let later calls with other arguments run undecided.
func TestAllowNeverSelectsAPersistentOption(t *testing.T) {
	for name, tc := range map[string]struct {
		opts  []PermOption
		allow string
		deny  string
	}{
		"always listed first": {
			[]PermOption{{OptionID: "a", Kind: "allow_always"}, {OptionID: "b", Kind: "allow_once"}, {OptionID: "c", Kind: "reject_once"}},
			"b", "c",
		},
		"always named by id only": {
			[]PermOption{{OptionID: "allow-always"}, {OptionID: "allow-once"}, {OptionID: "reject-always"}, {OptionID: "reject-once"}},
			"allow-once", "reject-once",
		},
		"only persistent allow offered": {
			[]PermOption{{OptionID: "a", Kind: "allow_always"}, {OptionID: "r", Kind: "reject_always"}},
			"allow-once", "r",
		},
	} {
		if got := pickOption(tc.opts, true); got != tc.allow {
			t.Fatalf("%s: allow answered %q, want %q", name, got, tc.allow)
		}
		if got := pickOption(tc.opts, false); got != tc.deny {
			t.Fatalf("%s: deny answered %q, want %q", name, got, tc.deny)
		}
	}
}
