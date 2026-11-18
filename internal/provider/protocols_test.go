package provider

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"strings"
	"testing"
)

func TestClaudeLoopDropsTranscriptBodies(t *testing.T) {
	pr, pw := io.Pipe()
	go func() {
		defer func() { _ = pw.Close() }()
		for range 50 {
			_, _ = fmt.Fprintf(pw, `{"type":"assistant","message":{"content":[{"type":"text","text":"%s"}]}}`+"\n", strings.Repeat("x", 200))
		}
		_, _ = fmt.Fprintln(pw, `{"type":"result","session_id":"sess-1"}`)
	}()
	observed := 0
	res, err := readProviderLoop(bufio.NewReader(pr), io.Discard, "sess-1", nil, "claude", func(Event) { observed++ })
	if err != nil {
		t.Fatal(err)
	}
	if res.Cursor != "sess-1" {
		t.Fatalf("cursor %q", res.Cursor)
	}
	if len(res.Events) != 0 {
		t.Fatalf("claude host keeps Cursor only, events %+v", res.Events)
	}
	if observed != 50 {
		t.Fatalf("observed %d transcript events, want 50", observed)
	}
}

// A numeric JSON-RPC request id must come back numeric, not as a quoted
// string: a mismatched id type is an invalid reply under the spec and
// providers that compare ids by raw value would never match it.
func TestPermissionReplyEchoesNumericIDUnchanged(t *testing.T) {
	for _, tc := range []struct {
		kind   string
		method string
	}{
		{"grok", "session/request_permission"},
		{"codex", "item/commandExecution/requestApproval"},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			pr, pw := io.Pipe()
			go func() {
				defer func() { _ = pw.Close() }()
				_, _ = fmt.Fprintf(pw, `{"id":7,"method":%q,"params":{"options":[{"id":"allow-once"},{"id":"reject-once"}]}}`+"\n", tc.method)
				_, _ = fmt.Fprintln(pw, `{"method":"turn/completed"}`)
			}()
			var out strings.Builder
			decide := func(options []Option, raw json.RawMessage) (string, bool) {
				return "reject-once", false
			}
			if _, err := readProviderLoop(bufio.NewReader(pr), &out, "", decide, tc.kind, nil); err != nil {
				t.Fatal(err)
			}
			line, _, _ := strings.Cut(out.String(), "\n")
			var reply struct {
				ID json.RawMessage `json:"id"`
			}
			if err := json.Unmarshal([]byte(line), &reply); err != nil {
				t.Fatalf("decode reply %q: %v", line, err)
			}
			if string(reply.ID) != "7" {
				t.Fatalf("permission reply id = %s, want numeric 7 echoed unchanged", reply.ID)
			}
		})
	}
}

func TestCodexNetworkApprovalDoesNotInheritExecuteGrant(t *testing.T) {
	var out strings.Builder
	called := false
	event, err := answerCodexRequest(&out, map[string]any{"id": 7, "method": "item/commandExecution/requestApproval", "params": map[string]any{"networkApprovalContext": map[string]string{"host": "example.com", "protocol": "https"}}}, func([]Option, json.RawMessage) (string, bool) { called = true; return "accept", true })
	if err != nil {
		t.Fatal(err)
	}
	var reply struct {
		Result struct {
			Decision string `json:"decision"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(out.String()), &reply); err != nil {
		t.Fatal(err)
	}
	if called || event.OptionID != "decline" || reply.Result.Decision != "decline" {
		t.Fatal("network approval inherited execution grant")
	}
}

func codexToolApprovalRequest(meta map[string]any) map[string]any {
	return map[string]any{"id": 9, "method": "mcpServer/elicitation/request", "params": map[string]any{
		"threadId": "t1", "turnId": "u1", "serverName": "docs", "mode": "form",
		"message":         `Allow the docs MCP server to run tool "write"?`,
		"requestedSchema": map[string]any{"type": "object", "properties": map[string]any{}},
		"_meta":           meta,
	}}
}

func codexToolMeta() map[string]any {
	return map[string]any{"codex_approval_kind": "mcp_tool_call", "tool_name": "write", "tool_params": map[string]any{"path": "a", "body": "x"}}
}

func answerElicitation(t *testing.T, msg map[string]any, decide Decide) (Event, string, map[string]any) {
	t.Helper()
	var out strings.Builder
	ev, err := answerCodexRequest(&out, msg, decide)
	if err != nil {
		t.Fatal(err)
	}
	var reply struct {
		ID     json.RawMessage `json:"id"`
		Result map[string]any  `json:"result"`
	}
	if err := json.Unmarshal([]byte(out.String()), &reply); err != nil {
		t.Fatalf("reply %q: %v", out.String(), err)
	}
	if string(reply.ID) != "9" {
		t.Fatalf("reply id %s", reply.ID)
	}
	action, _ := reply.Result["action"].(string)
	return ev, action, reply.Result
}

func TestCodexToolCallApprovalGoesThroughDecide(t *testing.T) {
	for _, allow := range []bool{true, false} {
		var decided struct {
			Title    string         `json:"title"`
			ToolName string         `json:"toolName"`
			Kind     string         `json:"kind"`
			RawInput map[string]any `json:"rawInput"`
		}
		var offered []Option
		ev, action, result := answerElicitation(t, codexToolApprovalRequest(codexToolMeta()), func(options []Option, raw json.RawMessage) (string, bool) {
			offered = options
			_ = json.Unmarshal(raw, &decided)
			if allow {
				return "accept", true
			}
			return "deny", false
		})
		want := "decline"
		if allow {
			want = "accept"
		}
		if action != want || ev.Kind != "permission" || ev.OptionID != want || len(ev.Call) != 0 {
			t.Fatalf("allow=%v action %q event %+v", allow, action, ev)
		}
		if decided.ToolName != "mcp__docs__write" || decided.Title != "mcp__docs__write" || decided.Kind != "other" || !maps.Equal(decided.RawInput, map[string]any{"path": "a", "body": "x"}) {
			t.Fatalf("decided %+v", decided)
		}
		if len(offered) != 2 || offered[0].ID != "accept" || offered[1].ID != "decline" {
			t.Fatalf("options %+v", offered)
		}
		// An accept carries no content and no persistence grant.
		if result["content"] != nil || result["_meta"] != nil {
			t.Fatalf("result %v", result)
		}
	}
}

func TestCodexToolCallApprovalWithoutDecideDeclines(t *testing.T) {
	_, action, _ := answerElicitation(t, codexToolApprovalRequest(codexToolMeta()), nil)
	if action != "decline" {
		t.Fatalf("action %q", action)
	}
}

// Anything but a readable tool-call approval is declined without asking
// decide, and is handed back for the host to record.
func TestCodexOtherElicitationsAreDeclinedAndReported(t *testing.T) {
	mutate := func(f func(p, meta map[string]any)) map[string]any {
		msg := codexToolApprovalRequest(codexToolMeta())
		p := msg["params"].(map[string]any)
		f(p, p["_meta"].(map[string]any))
		return msg
	}
	for name, msg := range map[string]map[string]any{
		"no meta":       mutate(func(p, _ map[string]any) { delete(p, "_meta") }),
		"other kind":    mutate(func(_, m map[string]any) { m["codex_approval_kind"] = "browser_auth" }),
		"no tool name":  mutate(func(_, m map[string]any) { delete(m, "tool_name") }),
		"empty name":    mutate(func(_, m map[string]any) { m["tool_name"] = "" }),
		"name not text": mutate(func(_, m map[string]any) { m["tool_name"] = 7 }),
		"no arguments":  mutate(func(_, m map[string]any) { delete(m, "tool_params") }),
		"args not map":  mutate(func(_, m map[string]any) { m["tool_params"] = "x" }),
		"args null":     mutate(func(_, m map[string]any) { m["tool_params"] = nil }),
		"no server":     mutate(func(p, _ map[string]any) { delete(p, "serverName") }),
		"url mode":      mutate(func(p, _ map[string]any) { p["mode"] = "url"; p["url"] = "https://x.example" }),
		"asks for data": mutate(func(p, _ map[string]any) {
			p["requestedSchema"] = map[string]any{"type": "object", "properties": map[string]any{"token": map[string]any{"type": "string"}}}
		}),
	} {
		t.Run(name, func(t *testing.T) {
			called := false
			ev, action, _ := answerElicitation(t, msg, func([]Option, json.RawMessage) (string, bool) { called = true; return "accept", true })
			if called || action != "decline" || ev.Kind != "permission" || ev.OptionID != "decline" {
				t.Fatalf("called=%v action %q event %+v", called, action, ev)
			}
			var call map[string]any
			if err := json.Unmarshal(ev.Call, &call); err != nil || call["toolName"] != "mcpServer/elicitation/request" {
				t.Fatalf("declined call %s: %v", ev.Call, err)
			}
			if strings.Contains(string(ev.Call), "Allow the docs") {
				t.Fatalf("server text recorded: %s", ev.Call)
			}
		})
	}
}

func TestCodexElicitationInTurnLoopContinues(t *testing.T) {
	pr, pw := io.Pipe()
	go func() {
		defer func() { _ = pw.Close() }()
		bad, _ := json.Marshal(map[string]any{"id": 1, "method": "mcpServer/elicitation/request", "params": map[string]any{"serverName": "docs", "mode": "url", "url": "https://x.example"}})
		good, _ := json.Marshal(codexToolApprovalRequest(codexToolMeta()))
		_, _ = fmt.Fprintf(pw, "%s\n%s\n%s\n", bad, good, `{"method":"turn/completed"}`)
	}()
	var out strings.Builder
	var observed []Event
	res, err := readProviderLoop(bufio.NewReader(pr), &out, "t1", func([]Option, json.RawMessage) (string, bool) { return "accept", true }, "codex", func(ev Event) { observed = append(observed, ev) })
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 2 || res.Events[0].OptionID != "decline" || res.Events[1].OptionID != "accept" || len(observed) != 2 {
		t.Fatalf("events %+v observed %+v", res.Events, observed)
	}
	if lines := strings.Count(out.String(), "\n"); lines != 2 {
		t.Fatalf("replies %q", out.String())
	}
}

func TestCodexUnknownRequestStillFailsTurn(t *testing.T) {
	var out strings.Builder
	if _, err := answerCodexRequest(&out, map[string]any{"id": 3, "method": "item/tool/call"}, nil); err == nil {
		t.Fatal("unknown request answered")
	}
}
