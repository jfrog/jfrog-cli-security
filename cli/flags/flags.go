package flags

import (
	"fmt"
	"strings"

	"github.com/jfrog/jfrog-cli-security/commands/git"

	"github.com/jfrog/jfrog-cli-core/v2/common/cliutils"
	pluginsCommon "github.com/jfrog/jfrog-cli-core/v2/plugins/common"
	"github.com/jfrog/jfrog-cli-core/v2/plugins/components"
	"github.com/jfrog/jfrog-cli-security/commands/xray/offlineupdate"
	"github.com/jfrog/jfrog-cli-security/utils"
)

// Command keys (grouped based on their namespace)
const (
	// Xray Command
	XrCurl        = "xr-curl"
	OfflineUpdate = "offline-update"

	// Application Command
	Detect = "detect"

	// Git Command
	GitCountContributors = "count-contributors"

	// Security scan Command
	XrScan        = "xr-scan"
	BuildScan     = "build-scan"
	DockerScan    = "docker scan"
	Audit         = "audit"
	CurationAudit = "curation-audit"
	Enrich        = "sbom-enrich"
	// TODO: Deprecated commands (remove at next CLI major version)
	AuditMvn    = "audit-maven"
	AuditGradle = "audit-gradle"
	AuditNpm    = "audit-npm"
	AuditGo     = "audit-go"
	AuditPip    = "audit-pip"
	AuditPipenv = "audit-pipenv"
)

// Mapping between security commands (key) and their flags (key).
var commandFlags = map[string][]string{
	// Xray Commands Keys
	XrCurl:        {ServerId},
	OfflineUpdate: {LicenseId, From, To, Version, Target, Stream, Periodic},
	// Application Commands Keys
	Detect: getFlagGroups(PlatformConnection),
	// Git Commands Keys
	GitCountContributors: {InputFile, ScmType, ScmApiUrl, Token, Owner, RepoName, Months, DetailedSummary},
	// Security scan Commands Keys
	Enrich:     append(getFlagGroups(PlatformConnection), Threads),
	BuildScan:  append(getFlagGroups(PlatformConnection, ControlOutputDisplay), Project, Vuln, Fail, Rescan),
	XrScan:     append(getFlagGroups(PlatformConnection, SpecFileConfig, ViolationContext, ControlOutputDisplay, FilterContent), Threads, Licenses, BypassArchiveLimits),
	DockerScan: append(getFlagGroups(ViolationContext, ControlOutputDisplay), ServerId, Licenses, BypassArchiveLimits, MinSeverity, FixableOnly),
	Audit: append(
		getFlagGroups(PlatformConnection, MultiTargetConfig, ControlScanTypes, ViolationContext, ControlOutputDisplay, FilterContent),
		InsecureTls, Licenses, ExcludeTestDeps, useWrapperAudit, DepType, RequirementsFile, ThirdPartyContextualAnalysis, Threads,
	),
	CurationAudit: {CurationOutput, WorkingDirs, Threads, RequirementsFile},
	// TODO: Deprecated commands (remove at next CLI major version)
	AuditMvn:    append(getFlagGroups(PlatformConnection, ViolationContext, ControlOutputDisplay), InsecureTls, ExclusionsAudit, Licenses, useWrapperAudit),
	AuditGradle: append(getFlagGroups(PlatformConnection, ViolationContext, ControlOutputDisplay), ExcludeTestDeps, ExclusionsAudit, useWrapperAudit, Licenses),
	AuditNpm:    append(getFlagGroups(PlatformConnection, ViolationContext, ControlOutputDisplay), DepType, ExclusionsAudit, Licenses),
	AuditGo:     append(getFlagGroups(PlatformConnection, ViolationContext, ControlOutputDisplay), ExclusionsAudit, Licenses),
	AuditPip:    append(getFlagGroups(PlatformConnection, ViolationContext, ControlOutputDisplay), RequirementsFile, ExclusionsAudit, Licenses),
	AuditPipenv: append(getFlagGroups(PlatformConnection, ViolationContext, ControlOutputDisplay), ExclusionsAudit, Licenses),
}

func GetCommandFlags(cmdKey string) []components.Flag {
	return pluginsCommon.GetCommandFlags(cmdKey, commandFlags, flagsMap)
}

// Grouping of flags by their purpose and usage.
var flagBundles = map[string][]string{
	PlatformConnection:    {url, user, password, accessToken, ServerId},
	MultiTargetConfig:     {WorkingDirs, ExclusionsAudit},
	SpecFileConfig:        {SpecFlag, scanRegexp, scanAnt},
	ControlScanTypes:      {Sca, Iac, Sast, Secrets, WithoutCA},
	ViolationContext:      {Project, Watches, RepoPath, Fail},
	ControlPackageManager: {Mvn, Gradle, Npm, Pnpm, Yarn, Nuget, Go, Pip, Pipenv, Poetry},
	ControlOutputDisplay:  {OutputFormat, ExtendedTable},
	FilterContent:         {MinSeverity, FixableOnly},
}

func getFlagGroups(names ...string) []string {
	var flags []string
	for _, name := range names {
		flags = append(flags, flagBundles[name]...)
	}
	return flags
}

// Security Flag keys mapped to their corresponding components. Flag definition.
var flagsMap = map[string]components.Flag{
	// Common flags for the commands
	Threads: components.NewStringFlag(Threads, "Number of working threads.", components.WithIntDefaultValue(cliutils.Threads)),

	// PlatformConnection
	ServerId:    components.NewStringFlag(ServerId, "Server ID configured using the config command."),
	url:         components.NewStringFlag(url, "JFrog Xray URL."),
	user:        components.NewStringFlag(user, "JFrog username."),
	password:    components.NewStringFlag(password, "JFrog password."),
	accessToken: components.NewStringFlag(accessToken, "JFrog access token."),
	InsecureTls: components.NewBoolFlag(InsecureTls, "Set to true to skip TLS certificates verification."),

	// MultiTargetConfig
	WorkingDirs: components.NewStringFlag(WorkingDirs, "A comma-separated list of relative working directories, to determine audit targets locations."),
	ExclusionsAudit: components.NewStringFlag(
		Exclusions,
		"List of exclusions separated by semicolons, utilized to skip sub-projects from undergoing an audit. These exclusions may incorporate the * and ? wildcards.",
		components.WithStrDefaultValue(strings.Join(utils.DefaultScaExcludePatterns, ";")),
	),

	// SpecFileConfig
	SpecFlag:      components.NewStringFlag(SpecFlag, "Path to a File Spec."),
	scanRecursive: components.NewBoolFlag(Recursive, "Set to false if you do not wish to collect artifacts in sub-folders to be scanned by Xray.", components.WithBoolDefaultValue(true)),
	scanRegexp:    components.NewBoolFlag(RegexpFlag, "Set to true to use a regular expression instead of wildcards expression to collect files to scan."),
	scanAnt:       components.NewBoolFlag(AntFlag, "Set to true to use an ant pattern instead of wildcards expression to collect files to scan."),

	// ControlScanTypes
	Sca:       components.NewBoolFlag(Sca, fmt.Sprintf("Selective scanners mode: Execute SCA (Software Composition Analysis) sub-scan. By default, runs both SCA and Contextual Analysis. Can be combined with --%s, --%s, --%s, and --%s.", Secrets, Sast, Iac, WithoutCA)),
	Iac:       components.NewBoolFlag(Iac, fmt.Sprintf("Selective scanners mode: Execute IaC sub-scan. Can be combined with --%s, --%s and --%s.", Sca, Secrets, Sast)),
	Sast:      components.NewBoolFlag(Sast, fmt.Sprintf("Selective scanners mode: Execute SAST sub-scan. Can be combined with --%s, --%s and --%s.", Sca, Secrets, Iac)),
	Secrets:   components.NewBoolFlag(Secrets, fmt.Sprintf("Selective scanners mode: Execute Secrets sub-scan. Can be combined with --%s, --%s and --%s.", Sca, Sast, Iac)),
	WithoutCA: components.NewBoolFlag(WithoutCA, fmt.Sprintf("Selective scanners mode: Disable Contextual Analysis scanner after SCA. Relevant only with --%s flag.", Sca)),

	// ViolationContext
	Project:  components.NewStringFlag(Project, "JFrog Artifactory project key."),
	Watches:  components.NewStringFlag(Watches, "A comma-separated list of Xray watches, to determine Xray's violations creation."),
	RepoPath: components.NewStringFlag(RepoPath, "Target repo path, to enable Xray to determine watches accordingly."),
	Fail:     components.NewBoolFlag(Fail, fmt.Sprintf("When using one of the flags --%s, --%s or --%s and a 'Fail build' rule is matched, the command will return exit code 3. Set to false if you'd like to see violations with exit code 0.", Watches, Project, RepoPath), components.WithBoolDefaultValue(true)),

	// ControlPackageManager
	Mvn:    components.NewBoolFlag(Mvn, "Set to true to request audit for a Maven project."),
	Gradle: components.NewBoolFlag(Gradle, "Set to true to request audit for a Gradle project."),
	Npm:    components.NewBoolFlag(Npm, "Set to true to request audit for a npm project."),
	Pnpm:   components.NewBoolFlag(Pnpm, "Set to true to request audit for a Pnpm project."),
	Yarn:   components.NewBoolFlag(Yarn, "Set to true to request audit for a Yarn project."),
	Nuget:  components.NewBoolFlag(Nuget, "Set to true to request audit for a .NET project."),
	Pip:    components.NewBoolFlag(Pip, "Set to true to request audit for a Pip project."),
	Pipenv: components.NewBoolFlag(Pipenv, "Set to true to request audit for a Pipenv project."),
	Poetry: components.NewBoolFlag(Poetry, "Set to true to request audit for a Poetry project."),
	Go:     components.NewBoolFlag(Go, "Set to true to request audit for a Go project."),

	// ControlOutputDisplay
	OutputFormat: components.NewStringFlag(
		OutputFormat,
		"Defines the output format of the command. Acceptable values are: table, json, simple-json and sarif. Note: the json format doesn't include information about scans that are included as part of the Advanced Security package.",
		components.WithStrDefaultValue("table"),
	),
	ExtendedTable: components.NewBoolFlag(ExtendedTable, "Set to true if you'd like the table to include extended fields such as 'CVSS' & 'Xray Issue Id'. Ignored if provided 'format' is not 'table'."),
	Licenses:      components.NewBoolFlag(Licenses, "Set to true if you'd like to receive licenses from Xray scanning."),

	// FilterContent
	MinSeverity: components.NewStringFlag(MinSeverity, "Set the minimum severity of issues to display. The following values are accepted: Low, Medium, High or Critical."),
	FixableOnly: components.NewBoolFlag(FixableOnly, "Set to true if you wish to display issues that have a fixed version only."),

	// Xray flags
	LicenseId: components.NewStringFlag(LicenseId, "Xray license ID.", components.SetMandatory(), components.WithHelpValue("Xray license ID")),
	From:      components.NewStringFlag(From, "From update date in YYYY-MM-DD format."),
	To:        components.NewStringFlag(To, "To update date in YYYY-MM-DD format."),
	Version:   components.NewStringFlag(Version, "Xray API version."),
	Target:    components.NewStringFlag(Target, "Target directory to download the updates to.", components.WithStrDefaultValue("./")),
	Stream:    components.NewStringFlag(Stream, fmt.Sprintf("Xray DBSync V3 stream, Possible values are: %s.", offlineupdate.NewValidStreams().GetValidStreamsString())),
	Periodic:  components.NewBoolFlag(Periodic, fmt.Sprintf("Set to true to get the Xray DBSync V3 Periodic Package (Use with %s flag).", Stream)),

	// Scan flags
	BypassArchiveLimits: components.NewBoolFlag(BypassArchiveLimits, "Set to true to bypass the indexer-app archive limits."),
	Rescan:              components.NewBoolFlag(Rescan, "Set to true when scanning an already successfully scanned build, for example after adding an ignore rule."),
	Vuln:                components.NewBoolFlag(Vuln, "Set to true if you'd like to receive an additional view of all vulnerabilities, regardless of the policy configured in Xray. Ignored if provided 'format' is 'sarif'."),

	// Tech config flags
	DepType: components.NewStringFlag(DepType, "[npm] Defines npm dependencies type. Possible values are: all, devOnly and prodOnly."),
	ThirdPartyContextualAnalysis: components.NewBoolFlag(
		ThirdPartyContextualAnalysis,
		"[npm] when set, the Contextual Analysis scan also uses the code of the project dependencies to determine the applicability of the vulnerability.",
		components.SetHiddenBoolFlag(),
	),
	RequirementsFile: components.NewStringFlag(RequirementsFile, "[Pip] Defines pip requirements file name. For example: 'requirements.txt'."),
	ExcludeTestDeps:  components.NewBoolFlag(ExcludeTestDeps, "[Gradle] Set to true if you'd like to exclude Gradle test dependencies from Xray scanning."),
	useWrapperAudit: components.NewBoolFlag(
		UseWrapper,
		"Set to false if you wish to not use the gradle or maven wrapper.",
		components.WithBoolDefaultValue(true),
	),

	// Curation flags
	CurationOutput: components.NewStringFlag(OutputFormat, "Defines the output format of the command. Acceptable values are: table, json.", components.WithStrDefaultValue("table")),

	// Git flags
	InputFile:       components.NewStringFlag(InputFile, "Path to an input file in YAML format contains multiple git providers. With this option, all other scm flags will be ignored and only git servers mentioned in the file will be examined.."),
	ScmType:         components.NewStringFlag(ScmType, fmt.Sprintf("SCM type. Possible values are: %s.", git.NewScmType().GetValidScmTypeString())),
	ScmApiUrl:       components.NewStringFlag(ScmApiUrl, "SCM API URL. For example: 'https://api.github.com'."),
	Token:           components.NewStringFlag(Token, fmt.Sprintf("SCM API token. In the absence of a flag, tokens should be passed in the %s enviroment variable, or in the corresponding environment variables '%s'.", git.GenericGitTokenEnvVar, git.NewScmType().GetOptionalScmTypeTokenEnvVars())),
	Owner:           components.NewStringFlag(Owner, "The format of the owner key depends on the Git provider: On GitHub and GitLab, the owner is typically an individual or an organization, On Bitbucket, the owner can also be a project. In the case of a private instance on Bitbucket, the individual or organization name should be prefixed with '~'."),
	RepoName:        components.NewStringFlag(RepoName, "List of semicolon-separated(;) repositories names to analyze, If not provided all repositories related to the provided owner will be analyzed."),
	Months:          components.NewStringFlag(Months, "Number of months to analyze.", components.WithIntDefaultValue(git.DefaultContContributorsMonths)),
	DetailedSummary: components.NewBoolFlag(DetailedSummary, "Set to true to get a contributors detailed summary."),
}

// Flags (keys), grouped based on their purpose
const (
	// Flags to configure the connection to the JFrog Platform.
	PlatformConnection = "platform-connection-flags"

	ServerId    = "server-id"
	url         = "url"
	user        = "user"
	password    = "password"
	accessToken = "access-token"

	// Flags to configure the targets (source code).
	MultiTargetConfig = "multi-target-config-source-flags"

	WorkingDirs     = "working-dirs"
	ExclusionsAudit = auditPrefix + Exclusions

	// Flags to configure pattern for targets using spec file and its options. (binary)
	SpecFileConfig = "spec-file-config-binary-flags"

	SpecFlag      = "spec"
	scanRecursive = scanPrefix + Recursive
	scanRegexp    = scanPrefix + RegexpFlag
	scanAnt       = scanPrefix + AntFlag

	// Flags to configure the requested scan types.
	ControlScanTypes = "control-scan-types-flags"

	Sca       = "sca"
	Iac       = "iac"
	Sast      = "sast"
	Secrets   = "secrets"
	WithoutCA = "without-contextual-analysis"

	// Flags to configure the violation context.
	ViolationContext = "violation-context-flags"

	Watches  = "watches"
	RepoPath = "repo-path"
	Project  = "project"
	Fail     = "fail"

	// Flags to configure the requested package manager.
	ControlPackageManager = "control-package-manager-flags"

	Mvn    = "mvn"
	Gradle = "gradle"
	Npm    = "npm"
	Pnpm   = "pnpm"
	Yarn   = "yarn"
	Nuget  = "nuget"
	Go     = "go"
	Pip    = "pip"
	Pipenv = "pipenv"
	Poetry = "poetry"

	// Flags to configure the output display.
	ControlOutputDisplay = "control-output-display-flags"

	OutputFormat  = "format"
	ExtendedTable = "extended-table"

	// Flags to configure the output content.
	FilterContent = "filter-content-flags"

	MinSeverity = "min-severity"
	FixableOnly = "fixable-only"
)

// Other flags (keys)
const (
	// Client certification flags
	InsecureTls = "insecure-tls"

	// Unique curation flags
	CurationOutput = "curation-format"

	// Unique offline-update flags keys
	LicenseId = "license-id"
	From      = "from"
	To        = "to"
	Version   = "version"
	Target    = "target"
	Stream    = "stream"
	Periodic  = "periodic"

	// Unique git flags
	InputFile       = "input-file"
	ScmType         = "scm-type"
	ScmApiUrl       = "scm-api-url"
	Token           = "token"
	Owner           = "owner"
	RepoName        = "repo-name"
	Months          = "months"
	DetailedSummary = "detailed-summary"

	// Unique scan and audit flags
	scanPrefix          = "scan-"
	Rescan              = "rescan"
	Vuln                = "vuln"
	BypassArchiveLimits = "bypass-archive-limits"

	// Unique audit flags
	auditPrefix                  = "audit-"
	useWrapperAudit              = auditPrefix + UseWrapper
	ExcludeTestDeps              = "exclude-test-deps"
	DepType                      = "dep-type"
	ThirdPartyContextualAnalysis = "third-party-contextual-analysis"
	RequirementsFile             = "requirements-file"

	// Common
	Licenses    = "licenses"
	UseWrapper  = "use-wrapper"
	Threads     = "threads"
	Recursive   = "recursive"
	RegexpFlag  = "regexp"
	AntFlag     = "ant"
	Exclusions  = "exclusions"
	IncludeDirs = "include-dirs"
)
