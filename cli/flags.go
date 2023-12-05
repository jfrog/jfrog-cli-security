package cli

import (
	"fmt"

	"github.com/jfrog/jfrog-cli-core/v2/plugins/components"
	"github.com/jfrog/jfrog-cli-core/v2/utils/cliutils"
	"github.com/jfrog/jfrog-cli-security/commands/offlineupdate"
)

const (
	// Security Commands Keys
	XrCurl        = "xr-curl"
	OfflineUpdate = "offline-update"
	XrScan        = "xr-scan"
	BuildScan     = "build-scan"
	DockerScan    = "docker scan"
	Audit         = "audit"
	CurationAudit = "curation-audit"

	// TODO: Deprecated commands (remove at next CLI major version)
	AuditMvn      = "audit-maven"
	AuditGradle   = "audit-gradle"
	AuditNpm      = "audit-npm"
	AuditGo       = "audit-go"
	AuditPip      = "audit-pip"
	AuditPipenv   = "audit-pipenv"

	// Base flags keys
	serverId = "server-id"
	xrUrl = "xr-url"
	user        = "user"
	password    = "password"
	accessToken = "access-token"

	// Generic command flags
	specFlag = "spec"
	threads  = "threads"

	// Unique offline-update flags keys
	LicenseId = "license-id"
	From      = "from"
	To        = "to"
	Version   = "version"
	Target    = "target"
	Stream    = "stream"
	Periodic  = "periodic"

	// Unique scan flags
	scanPrefix          = "scan-"
	scanRecursive       = scanPrefix + recursive
	scanRegexp          = scanPrefix + regexpFlag
	scanAnt             = scanPrefix + antFlag
	xrOutput            = "format"
	BypassArchiveLimits = "bypass-archive-limits"
)

// Mapping between security commands (key) and their flags (key).
var commandFlags = map[string][]string{
	XrCurl:        {serverId},
	OfflineUpdate: {LicenseId, From, To, Version, Target, Stream, Periodic},
	XrScan: {
		xrUrl, user, password, accessToken, serverId, specFlag, threads, scanRecursive, scanRegexp, scanAnt,
		Project, watches, repoPath, licenses, xrOutput, fail, ExtendedTable, BypassArchiveLimits, MinSeverity, FixableOnly,
	},
}

// Security Flag keys mapped to their corresponding components.Flag definition.
var flagsMap = map[string]components.Flag{
	serverId: components.StringFlag{
		Name:        serverId,
		Description: "Server ID configured using the config command.` `",
	},
	LicenseId: components.StringFlag{
		Name:        LicenseId,
		Mandatory:   true,
		Description: "Xray license ID.` `",
	},
	From: components.StringFlag{
		Name:        From,
		Description: "From update date in YYYY-MM-DD format.` `",
	},
	To: components.StringFlag{
		Name:        To,
		Description: "To update date in YYYY-MM-DD format.` `",
	},
	Version: components.StringFlag{
		Name:        Version,
		Description: "Xray API version.` `",
	},
	Target: components.StringFlag{
		Name:        Target,
		DefaultValue: "./",
		Description: "Target directory to download the updates to.` `",
	},
	Stream: components.StringFlag{
		Name:        Stream,
		Description: fmt.Sprintf("Xray DBSync V3 stream, Possible values are: %s.` `", offlineupdate.NewValidStreams().GetValidStreamsString()),
	},
	Periodic: components.BoolFlag{
		Name:        Periodic,
		Description: fmt.Sprintf("Set to true to get the Xray DBSync V3 Periodic Package (Use with %s flag).` `", Stream), 
	},
}

func GetCommandFlags(cmdKey string) []components.Flag {
	return cliutils.GetCommandFlags(cmdKey, commandFlags, flagsMap)
}
