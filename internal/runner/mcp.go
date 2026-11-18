package runner

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/sannrox/rusui/internal/acp"
	"github.com/sannrox/rusui/internal/guest"
)

// turnTokenEnv names the variable that carries the turn credential. Guests
// that read MCP headers from the environment reference it, so the value never
// lands in argv or a config file.
const turnTokenEnv = "RUSUI_TURN_TOKEN"

// MCPServer is a remote MCP tool server the plane names for the turn.
type MCPServer struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

// mcpServers returns the turn's remote MCP servers. In gateway mode every
// server must be the gateway; anything else is refused before the guest
// starts, so a direct connection never opens.
func (a *Assignment) mcpServers() ([]MCPServer, error) {
	if a == nil {
		return nil, nil
	}
	if a.MCPGateway != "" {
		for _, s := range a.MCPServers {
			if s.URL != a.MCPGateway {
				return nil, fmt.Errorf("mcp: direct server %q refused in gateway mode", s.Name)
			}
		}
	}
	return a.MCPServers, nil
}

// authenticated reports whether s receives the turn credential. Only the
// gateway does; a direct server never sees a plane credential.
func (a *Assignment) authenticated(s MCPServer) bool {
	return a.MCPGateway != "" && s.URL == a.MCPGateway
}

// acpMCPServers maps the servers to ACP session/new and session/load entries.
func acpMCPServers(a *Assignment, servers []MCPServer) []any {
	out := make([]any, 0, len(servers))
	for _, s := range servers {
		headers := []acp.HTTPHeader{}
		if a.authenticated(s) {
			headers = append(headers, acp.HTTPHeader{Name: "Authorization", Value: "Bearer " + a.guestToken()})
		}
		out = append(out, acp.MCPServer{Type: "http", Name: s.Name, URL: s.URL, Headers: headers})
	}
	return out
}

// mcpArgv adds the servers to a native guest's command line. The credential
// is referenced by environment variable name only. Claude's can_use_tool
// request and Codex's per-call tool approval put every tool-server call
// through the permission fence.
func mcpArgv(a *Assignment, argv []string, servers []MCPServer) []string {
	if len(servers) == 0 {
		return argv
	}
	switch a.Guest {
	case guest.KindClaude:
		return claudeMCPArgv(a, argv, servers)
	case guest.KindCodex:
		return codexMCPArgv(a, argv, servers)
	}
	return argv
}

// codexMCPArgv sets every server's tool approval mode to prompt, so the
// app-server asks before each call, and sets no per-tool override. The
// guest's home is fresh and repository Codex config is refused, so these
// overrides are the only source of the mode.
func codexMCPArgv(a *Assignment, argv []string, servers []MCPServer) []string {
	var b strings.Builder
	b.WriteByte('{')
	for i, s := range servers {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `%s={url=%s,default_tools_approval_mode="prompt"`, tomlString(s.Name), tomlString(s.URL))
		if a.authenticated(s) {
			fmt.Fprintf(&b, `,bearer_token_env_var=%s`, tomlString(turnTokenEnv))
		}
		b.WriteByte('}')
	}
	b.WriteByte('}')
	return append(argv, "-c", "mcp_servers="+b.String())
}

// tomlString quotes s as a TOML basic string. JSON string escapes are a
// subset of TOML's.
func tomlString(s string) string {
	raw, _ := json.Marshal(s)
	return string(raw)
}

func claudeMCPArgv(a *Assignment, argv []string, servers []MCPServer) []string {
	type entry struct {
		Type    string            `json:"type"`
		URL     string            `json:"url"`
		Headers map[string]string `json:"headers,omitempty"`
	}
	cfg := map[string]map[string]entry{"mcpServers": {}}
	for _, s := range servers {
		e := entry{Type: "http", URL: s.URL}
		if a.authenticated(s) {
			e.Headers = map[string]string{"Authorization": "Bearer ${" + turnTokenEnv + "}"}
		}
		cfg["mcpServers"][s.Name] = e
	}
	raw, _ := json.Marshal(cfg)
	return append(argv, "--mcp-config", string(raw))
}
