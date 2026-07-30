package sast_server

func GetDescription() string {
	return "Runs a local source code analysis as a local SAST server, allowing access to tools which reflect source code analysis"
}

func GetAIDescription() string {
	return `Start a local HTTP server that exposes JFrog SAST source-code analysis endpoints, enabling other tools (IDE plugins, AI agents, custom integrations) to request scans over HTTP instead of spawning the CLI per call. Use when a long-running client needs to invoke SAST repeatedly against changing files.

When to use:
- Back an IDE extension or AI agent with a persistent local SAST endpoint.
- Avoid analyzerManager startup overhead by serving multiple scan requests from one process.

Prerequisites:
- A configured JFrog Platform server (jf c add) with JFrog Advanced Security entitlement.
- analyzerManager binary available (auto-installed on first run).
- A free TCP port for the server to bind to (passed via --port).

Common patterns:
  $ jf sast-server --port=8080
  $ jf sast-server --port=9000

Gotchas:
- --port is mandatory; the command exits with an error if it is omitted.
- The server binds only to localhost; it is not intended for remote access.
- The command is currently hidden from top-level help.

Related: jf audit, jf source-mcp`
}
