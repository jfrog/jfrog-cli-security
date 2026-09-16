package source_mcp

import (
	"github.com/jfrog/jfrog-cli-core/v2/plugins/components"
)

func GetDescription() string {
	return "Runs a local source code analysis as a local MCP server, allowing access to tools which reflect source code analysis"
}

func GetAIDescription() string {
	return `Launch a local Model Context Protocol (MCP) server that exposes JFrog source-code analysis (SCA + JAS scans) as MCP tools over stdio. Use when an AI coding agent needs interactive, tool-callable access to scan results on the developer's machine; the agent (Claude Code, Cursor, etc.) starts this process and communicates via JSON-RPC on stdin/stdout.

When to use:
- Wire JFrog security scanning into an MCP-aware AI client as a local tool provider.
- Provide an agent with on-demand vulnerability, secret, SAST, and IaC scans of the user's codebase.

Prerequisites:
- A configured JFrog Platform server (jf c add) with Xray and JFrog Advanced Security entitlements.
- analyzerManager binary available (auto-installed on first run).
- The host process must be an MCP client capable of speaking JSON-RPC over the spawned process's stdio.

Common patterns:
  $ jf source-mcp /path/to/project
  $ jf source-mcp ./

Gotchas:
- This command is intended to be spawned by an MCP client, not run interactively in a terminal; stdout is reserved for JSON-RPC frames.
- Logs go to stderr; do not pipe stderr into the MCP transport.
- The command is currently hidden from top-level help while the integration matures.

Related: jf audit, jf scan, jf sast-server`
}

func GetArguments() []components.Argument {
	return []components.Argument{{Name: "Source path", Description: `Specifies the local file system path of source code to analyze.`}}
}
