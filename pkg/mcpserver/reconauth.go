package mcpserver

import (
	"os"
	"strings"

	"github.com/tuangatech/hacker-five/pkg/recon"
	"github.com/tuangatech/hacker-five/pkg/scanner/httpclient"
)

// reconAuthEnv lets the operator, when starting the MCP server, have recon
// carry their owner token (LT-187). It is deliberately an environment switch and
// not a tool parameter: the plan tool runs recon before the human approval
// prompt, so a flag the calling model could set would authenticate recon with no
// gate in front of it. The operator's choice to start the server with it is the
// consent. The token itself comes from plan's auth_token, else HACKERFIVE_AUTH_TOKEN.
const reconAuthEnv = "HACKERFIVE_RECON_AUTH"

// reconAuthParts returns the client middleware and recon options for an
// authenticated recon, plus one note for the tool's warnings, or nothing when
// the switch is off. With the switch on but no token it degrades to an
// unauthenticated recon and says so, so nobody believes it was authenticated.
func reconAuthParts(target, token string) (mws []httpclient.Middleware, opts []recon.Option, note string) {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(reconAuthEnv))) {
	case "1", "true", "yes", "on":
	default:
		return nil, nil, ""
	}
	if token == "" {
		token = os.Getenv("HACKERFIVE_AUTH_TOKEN")
	}
	cred, err := recon.NewCredential(target, token, "", "")
	if err != nil {
		return nil, nil, "recon-auth: " + reconAuthEnv + " is set but recon ran unauthenticated: " + err.Error()
	}
	return []httpclient.Middleware{cred.Middleware()}, []recon.Option{cred.Option()}, cred.Note()
}
