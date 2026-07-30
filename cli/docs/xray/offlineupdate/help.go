package offlineupdate

func GetDescription() string {
	return "Download Xray offline updates."
}

func GetAIDescription() string {
	return `Download Xray vulnerability/component database updates as offline bundles so they can be loaded into an air-gapped Xray instance. Use when an agent operates in (or supplies updates to) a network-isolated environment that cannot reach the JFrog update servers directly.

When to use:
- Refresh an air-gapped Xray's vulnerability database.
- Periodically mirror Xray updates to an internal artifact store.
- Stage a one-shot update window between two dates.

Prerequisites:
- A valid Xray offline-update license ID (--license-id is mandatory).
- Network access to https://updates.jfrog.io from the host running the command.
- Sufficient local disk space at --target for the downloaded bundle.

Common patterns:
  $ jf xr offline-update --license-id=ABC-123 --version=3
  $ jf xr ou --license-id=ABC-123 --stream=core --periodic --target=./xray-updates
  $ jf xr offline-update --license-id=ABC-123 --from=2024-01-01 --to=2024-02-01

Gotchas:
- --license-id is required; the command exits with an error if omitted.
- --periodic is only valid together with --stream.
- --from and --to must both be set when using V1 date-range mode and use YYYY-MM-DD format.
- Stream values are validated; an invalid --stream value rejects the call.

Related: jf xr curl, jf c show`
}
