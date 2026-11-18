package acp

import "strings"

// Decision is the plane's answer to session/request_permission.
type Decision struct {
	Matched bool
	Allow   bool
}

// PermissionGate maps a permission request onto policy. A request with
// no match is denied and surfaced as an approval.
type PermissionGate interface {
	Decide(PermissionParams) Decision
}

// DenyUnmatched refuses every request. v1 policy.yaml has no ACP tool
// rules, so this is the production gate.
type DenyUnmatched struct{}

func (DenyUnmatched) Decide(PermissionParams) Decision {
	return Decision{Matched: false, Allow: false}
}

// pickOption answers with one of the guest's options. A plane deny never
// selects an option whose id or kind looks like allow, whatever the guest
// offered; with no reject option it answers a synthesized reject-once. An
// allow never selects an option that persists ("always", by id or kind): it
// covers this call only, so a later call with other arguments is decided
// again. With no once-only allow offered it answers a synthesized
// allow-once.
func pickOption(opts []PermOption, allow bool) string {
	if !allow {
		var fallback string
		for _, o := range opts {
			if !looksLike(o, "reject", "deny") || looksLike(o, "allow") {
				continue
			}
			if !looksLike(o, "always") {
				return o.OptionID
			}
			if fallback == "" {
				fallback = o.OptionID
			}
		}
		if fallback != "" {
			return fallback
		}
		return "reject-once"
	}
	for _, o := range opts {
		if looksLike(o, "allow") && !looksLike(o, "always") {
			return o.OptionID
		}
	}
	return "allow-once"
}

func looksLike(o PermOption, words ...string) bool {
	id, kind := strings.ToLower(o.OptionID), strings.ToLower(o.Kind)
	for _, w := range words {
		if strings.Contains(id, w) || strings.Contains(kind, w) {
			return true
		}
	}
	return false
}
