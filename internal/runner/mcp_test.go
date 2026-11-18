package runner

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sannrox/rusui/internal/acp"
	"github.com/sannrox/rusui/internal/guest"
	"github.com/sannrox/rusui/internal/store"
)

const testGateway = "https://gateway.example/mcp"

func gatewayAssignment(kind string) *Assignment {
	return &Assignment{
		Guest:      kind,
		GuestGrant: "grant-secret-value-0123456789",
		MCPGateway: testGateway,
		MCPServers: []MCPServer{{Name: "gateway", URL: testGateway}},
	}
}

func TestGatewayModeRefusesDirectServer(t *testing.T) {
	a := gatewayAssignment(guest.KindGrok)
	a.MCPServers = append(a.MCPServers, MCPServer{Name: "docs", URL: "https://tools.example/mcp"})
	// The refusal comes before the guest home or process exists.
	if _, _, err := GuestHost(&Client{})(a, t.TempDir()); err == nil || !strings.Contains(err.Error(), "refused in gateway mode") {
		t.Fatalf("direct server accepted: %v", err)
	}
}

func TestGatewayACPEntryCarriesTurnCredential(t *testing.T) {
	a := gatewayAssignment(guest.KindGrok)
	got := acpMCPServers(a, a.MCPServers)
	want := acp.MCPServer{Type: "http", Name: "gateway", URL: testGateway, Headers: []acp.HTTPHeader{{Name: "Authorization", Value: "Bearer " + a.GuestGrant}}}
	if len(got) != 1 || !slices.Equal(got[0].(acp.MCPServer).Headers, want.Headers) || got[0].(acp.MCPServer).URL != want.URL {
		t.Fatalf("entries %+v", got)
	}
	// A direct server outside gateway mode gets no plane credential.
	direct := &Assignment{GuestGrant: a.GuestGrant, MCPServers: []MCPServer{{Name: "docs", URL: "https://tools.example/mcp"}}}
	if h := acpMCPServers(direct, direct.MCPServers)[0].(acp.MCPServer).Headers; len(h) != 0 {
		t.Fatalf("direct headers %+v", h)
	}
}

func TestNativeGatewayArgvReferencesCredentialByName(t *testing.T) {
	a := gatewayAssignment(guest.KindClaude)
	argv := strings.Join(mcpArgv(a, nil, a.MCPServers), " ")
	if strings.Contains(argv, a.GuestGrant) {
		t.Fatalf("argv leaks the credential: %s", argv)
	}
	if !strings.Contains(argv, testGateway) || !strings.Contains(argv, turnTokenEnv) {
		t.Fatalf("argv %s", argv)
	}
}

// Codex asks before each call to a server whose approval mode is prompt, so
// every listed server is sent with that mode and no per-tool override.
func TestCodexToolServersAreSentWithPromptMode(t *testing.T) {
	a := gatewayAssignment(guest.KindCodex)
	a.MCPGateway = ""
	a.MCPServers = []MCPServer{{Name: "docs", URL: "https://tools.example/mcp"}, {Name: "wiki", URL: "https://wiki.example/mcp"}}
	argv := mcpArgv(a, []string{"codex", "app-server"}, a.MCPServers)
	want := []string{"codex", "app-server", "-c", `mcp_servers={"docs"={url="https://tools.example/mcp",default_tools_approval_mode="prompt"},"wiki"={url="https://wiki.example/mcp",default_tools_approval_mode="prompt"}}`}
	if !slices.Equal(argv, want) {
		t.Fatalf("codex argv %q\nwant %q", argv, want)
	}
}

func TestCodexGatewayReferencesCredentialByName(t *testing.T) {
	a := gatewayAssignment(guest.KindCodex)
	argv := strings.Join(mcpArgv(a, nil, a.MCPServers), " ")
	if strings.Contains(argv, a.GuestGrant) {
		t.Fatalf("argv leaks the credential: %s", argv)
	}
	want := `"gateway"={url="` + testGateway + `",default_tools_approval_mode="prompt",bearer_token_env_var="` + turnTokenEnv + `"}`
	if !strings.Contains(argv, want) {
		t.Fatalf("argv %s\nwant %s", argv, want)
	}
}

func TestCodexToolServerNamesAreQuoted(t *testing.T) {
	a := &Assignment{Guest: guest.KindCodex, MCPServers: []MCPServer{{Name: `a"b.c`, URL: "https://x.example/mcp"}}}
	argv := mcpArgv(a, nil, a.MCPServers)
	if got := argv[len(argv)-1]; !strings.HasPrefix(got, `mcp_servers={"a\"b.c"={url=`) {
		t.Fatalf("unquoted name: %s", got)
	}
}

func TestNoToolServersLeavesCodexArgvAlone(t *testing.T) {
	a := gatewayAssignment(guest.KindCodex)
	if argv := mcpArgv(a, []string{"codex"}, nil); !slices.Equal(argv, []string{"codex"}) {
		t.Fatalf("argv %v", argv)
	}
}

// Each tool-server call's approval request goes through the plane's gate: a
// matching allow accepts that call, a reject or an unmatched call is declined,
// and a request that is not a readable approval is declined and recorded.
func TestCodexToolServerApprovalsGoThroughPermissionFence(t *testing.T) {
	input, guestOut := io.Pipe()
	guestIn, output := io.Pipe()
	t.Cleanup(func() { _ = input.Close(); _ = guestOut.Close(); _ = guestIn.Close(); _ = output.Close() })
	approval := func(id int, tool string) map[string]any {
		return map[string]any{"id": id, "method": "mcpServer/elicitation/request", "params": map[string]any{
			"threadId": "fixture", "serverName": "docs", "mode": "form", "message": "Allow?",
			"requestedSchema": map[string]any{"type": "object", "properties": map[string]any{}},
			"_meta":           map[string]any{"codex_approval_kind": "mcp_tool_call", "tool_name": tool, "tool_params": map[string]any{"path": tool}},
		}}
	}
	actions := make(chan []string, 1)
	go func() {
		scan := bufio.NewScanner(guestIn)
		send := func(v any) { raw, _ := json.Marshal(v); _, _ = fmt.Fprintln(guestOut, string(raw)) }
		var got []string
		for scan.Scan() {
			var msg map[string]any
			if json.Unmarshal(scan.Bytes(), &msg) != nil {
				return
			}
			switch msg["method"] {
			case "initialize":
				send(map[string]any{"id": msg["id"], "result": map[string]any{"userAgent": "codex-fixture"}})
			case "thread/start":
				send(map[string]any{"id": msg["id"], "result": map[string]any{"thread": map[string]any{"id": "fixture"}}})
			case "turn/start":
				send(map[string]any{"id": msg["id"], "result": map[string]any{}})
				send(approval(11, "read"))
			}
			if result, ok := msg["result"].(map[string]any); ok {
				got = append(got, fmt.Sprint(msg["id"], ":", result["action"]))
				switch len(got) {
				case 1:
					send(approval(12, "drop"))
				case 2:
					send(approval(13, "write"))
				case 3:
					send(map[string]any{"id": 14, "method": "mcpServer/elicitation/request", "params": map[string]any{"serverName": "docs", "mode": "url", "message": "log in", "url": "https://x.example", "elicitationId": "e"}})
				case 4:
					actions <- got
					send(map[string]any{"method": "turn/completed", "params": map[string]any{"turn": map[string]any{"status": "completed"}}})
					return
				}
			}
		}
	}()
	log := &receiptLog{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	a := &Assignment{
		Guest: guest.KindCodex, GuestSpec: guest.Entry{Protocol: guest.ProtocolCodex},
		ExecutionMode: store.ExecutionUser,
		Permissions:   []acp.Rule{{Tool: "mcp__docs__read"}, {Tool: "mcp__docs__drop", Action: acp.RuleReject}},
	}
	if _, err := HostACP(ctx, a, &acp.Client{In: input, Out: output, Rec: log}, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(<-actions, " "), "11:accept 12:decline 13:decline 14:decline"; got != want {
		t.Fatalf("replies %s, want %s", got, want)
	}
	var rows []string
	for _, row := range log.rows {
		if row.Type == acp.ActionPermission || row.Type == acp.ActionApproval {
			raw, _ := json.Marshal(row.Body)
			var p struct {
				ToolCall struct {
					ToolName string `json:"toolName"`
				} `json:"toolCall"`
			}
			_ = json.Unmarshal(raw, &p)
			rows = append(rows, row.Type+" "+row.Reason+" "+p.ToolCall.ToolName)
		}
	}
	want := strings.Join([]string{
		"acp.session.request_permission recorded mcp__docs__read",
		"acp.session.request_permission recorded mcp__docs__drop",
		"acp.approval denied mcp__docs__drop",
		"acp.session.request_permission recorded mcp__docs__write",
		"acp.approval permission_unmatched mcp__docs__write",
		"acp.approval denied mcpServer/elicitation/request",
	}, "\n")
	if got := strings.Join(rows, "\n"); got != want {
		t.Fatalf("receipts\n%s\nwant\n%s", got, want)
	}
}
