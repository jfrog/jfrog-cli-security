package docs

import (
	"fmt"
	"github.com/jfrog/jfrog-cli-security/commands/git"
	"strings"

	"github.com/jfrog/jfrog-cli-core/v2/common/cliutils"
	pluginsCommon "github.com/jfrog/jfrog-cli-core/v2/plugins/common"
	"github.com/jfrog/jfrog-cli-core/v2/plugins/components"
	"github.com/jfrog/jfrog-cli-security/commands/xray/offlineupdate"
	"github.com/jfrog/jfrog-cli-security/utils"
)

const (
	// Security Commands Keys
	XrCurl               = "xr-curl"
	OfflineUpdate        = "offline-update"
	XrScan               = "xr-scan"
	BuildScan            = "build-scan"
	DockerScan           = "docker scan"
	Audit                = "audit"
	CurationAudit        = "curation-audit"
	GitCountContributors = "count-contributors"
	Enrich               = "sbom-enrich"

	// TODO: Deprecated commands (remove at next CLI major version)
	AuditMvn    = "audit-maven"
	AuditGradle = "audit-gradle"
	AuditNpm    = "audit-npm"
	AuditGo     = "audit-go"
	AuditPip    = "audit-pip"
	AuditPipenv = "audit-pipenv"
)

const (
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
)

const (
	Sca       = "sca"
	Iac       = "iac"
	Sast      = "sast"
	Secrets   = "secrets"
	WithoutCA = "without-contextual-analysis"
)

const (
	// Base flags keys
	ServerId    = "server-id"
	url         = "url"
	user        = "user"
	password    = "password"
	accessToken = "access-token"

	// Client certification flags
	InsecureTls = "insecure-tls"

	// Generic command flags
	SpecFlag    = "spec"
	Threads     = "threads"
	Recursive   = "recursive"
	RegexpFlag  = "regexp"
	AntFlag     = "ant"
	Project     = "project"
	Exclusions  = "exclusions"
	IncludeDirs = "include-dirs"
	UseWrapper  = "use-wrapper"
)

const (
	// Unique offline-update flags keys
	LicenseId = "license-id"
	From      = "from"
	To        = "to"
	Version   = "version"
	Target    = "target"
	Stream    = "stream"
	Periodic  = "periodic"

	// Unique scan and audit flags
	scanPrefix          = "scan-"
	scanRecursive       = scanPrefix + Recursive
	scanRegexp          = scanPrefix + RegexpFlag
	scanAnt             = scanPrefix + AntFlag
	OutputFormat        = "format"
	BypassArchiveLimits = "bypass-archive-limits"
	Watches             = "watches"
	RepoPath            = "repo-path"
	Licenses            = "licenses"
	Fail                = "fail"
	ExtendedTable       = "extended-table"
	MinSeverity         = "min-severity"
	FixableOnly         = "fixable-only"
	Rescan              = "rescan"
	Vuln                = "vuln"

	// Unique audit flags
	auditPrefix                  = "audit-"
	ExclusionsAudit              = auditPrefix + Exclusions
	useWrapperAudit              = auditPrefix + UseWrapper
	ExcludeTestDeps              = "exclude-test-deps"
	DepType                      = "dep-type"
	ThirdPartyContextualAnalysis = "third-party-contextual-analysis"
	RequirementsFile             = "requirements-file"
	WorkingDirs                  = "working-dirs"

	// Unique curation flags
	CurationOutput = "curation-format"

	// Unique git flags
	ScmType         = "scm-type"
	ScmApiUrl       = "scm-api-url"
	Token           = "token"
	Owner           = "owner"
	RepoName        = "repo-name"
	Months          = "months"
	DetailedSummary = "detailed-summary"
)

// Mapping between security commands (key) and their flags (key).
var commandFlags = map[string][]string{
	XrCurl:        {ServerId},
	OfflineUpdate: {LicenseId, From, To, Version, Target, Stream, Periodic},
	XrScan: {
		url, user, password, accessToken, ServerId, SpecFlag, Threads, scanRecursive, scanRegexp, scanAnt,
		Project, Watches, RepoPath, Licenses, OutputFormat, Fail, ExtendedTable, BypassArchiveLimits, MinSeverity, FixableOnly,
	},
	Enrich: {
		url, user, password, accessToken, ServerId, SpecFlag, Threads,
	},
	BuildScan: {
		url, user, password, accessToken, ServerId, Project, Vuln, OutputFormat, Fail, ExtendedTable, Rescan,
	},
	DockerScan: {
		ServerId, Project, Watches, RepoPath, Licenses, OutputFormat, Fail, ExtendedTable, BypassArchiveLimits, MinSeverity, FixableOnly,
	},
	Audit: {
		url, user, password, accessToken, ServerId, InsecureTls, Project, Watches, RepoPath, Licenses, OutputFormat, ExcludeTestDeps,
		useWrapperAudit, DepType, RequirementsFile, Fail, ExtendedTable, WorkingDirs, ExclusionsAudit, Mvn, Gradle, Npm,
		Pnpm, Yarn, Go, Nuget, Pip, Pipenv, Poetry, MinSeverity, FixableOnly, ThirdPartyContextualAnalysis, Threads,
		Sca, Iac, Sast, Secrets, WithoutCA,
	},
	CurationAudit: {
		CurationOutput, WorkingDirs, Threads, RequirementsFile,
	},
	GitCountContributors: {
		ScmType, ScmApiUrl, Token, Owner, RepoName, Months, DetailedSummary,
	},
	// TODO: Deprecated commands (remove at next CLI major version)
	AuditMvn: {
		url, user, password, accessToken, ServerId, InsecureTls, Project, ExclusionsAudit, Watches, RepoPath, Licenses, OutputFormat, Fail, ExtendedTable, useWrapperAudit,
	},
	AuditGradle: {
		url, user, password, accessToken, ServerId, ExcludeTestDeps, ExclusionsAudit, useWrapperAudit, Project, Watches, RepoPath, Licenses, OutputFormat, Fail, ExtendedTable,
	},
	AuditNpm: {
		url, user, password, accessToken, ServerId, DepType, Project, ExclusionsAudit, Watches, RepoPath, Licenses, OutputFormat, Fail, ExtendedTable,
	},
	AuditGo: {
		url, user, password, accessToken, ServerId, Project, ExclusionsAudit, Watches, RepoPath, Licenses, OutputFormat, Fail, ExtendedTable,
	},
	AuditPip: {
		url, user, password, accessToken, ServerId, RequirementsFile, Project, ExclusionsAudit, Watches, RepoPath, Licenses, OutputFormat, Fail, ExtendedTable,
	},
	AuditPipenv: {
		url, user, password, accessToken, ServerId, Project, ExclusionsAudit, Watches, RepoPath, Licenses, OutputFormat, ExtendedTable,
	},
}

// Security Flag keys mapped to their corresponding components.Flag definition.
var flagsMap = map[string]components.Flag{
	// Common commands flags
	ServerId:    components.NewStringFlag(ServerId, "Server ID configured using the config command."),
	url:         components.NewStringFlag(url, "JFrog Xray URL."),
	user:        components.NewStringFlag(user, "JFrog username."),
	password:    components.NewStringFlag(password, "JFrog password."),
	accessToken: components.NewStringFlag(accessToken, "JFrog access token."),
	Threads:     components.NewStringFlag(Threads, "Number of working threads.", components.WithIntDefaultValue(cliutils.Threads)),
	// Xray flags
	LicenseId: components.NewStringFlag(LicenseId, "Xray license ID.", components.SetMandatory(), components.WithHelpValue("Xray license ID")),
	From:      components.NewStringFlag(From, "From update date in YYYY-MM-DD format."),
	To:        components.NewStringFlag(To, "To update date in YYYY-MM-DD format."),
	Version:   components.NewStringFlag(Version, "Xray API version."),
	Target:    components.NewStringFlag(Target, "Target directory to download the updates to.", components.WithStrDefaultValue("./")),
	Stream:    components.NewStringFlag(Stream, fmt.Sprintf("Xray DBSync V3 stream, Possible values are: %s.", offlineupdate.NewValidStreams().GetValidStreamsString())),
	Periodic:  components.NewBoolFlag(Periodic, fmt.Sprintf("Set to true to get the Xray DBSync V3 Periodic Package (Use with %s flag).", Stream)),
	// Scan flags
	SpecFlag:      components.NewStringFlag(SpecFlag, "Path to a File Spec."),
	scanRecursive: components.NewBoolFlag(Recursive, "Set to false if you do not wish to collect artifacts in sub-folders to be scanned by Xray.", components.WithBoolDefaultValue(true)),
	scanRegexp:    components.NewBoolFlag(RegexpFlag, "Set to true to use a regular expression instead of wildcards expression to collect files to scan."),
	scanAnt:       components.NewBoolFlag(AntFlag, "Set to true to use an ant pattern instead of wildcards expression to collect files to scan."),
	Project:       components.NewStringFlag(Project, "JFrog Artifactory project key."),
	Watches:       components.NewStringFlag(Watches, "A comma-separated list of Xray watches, to determine Xray's violations creation."),
	RepoPath:      components.NewStringFlag(RepoPath, "Target repo path, to enable Xray to determine watches accordingly."),
	Licenses:      components.NewBoolFlag(Licenses, "Set to true if you'd like to receive licenses from Xray scanning."),
	OutputFormat: components.NewStringFlag(
		OutputFormat,
		"Defines the output format of the command. Acceptable values are: table, json, simple-json and sarif. Note: the json format doesn't include information about scans that are included as part of the Advanced Security package.",
		components.WithStrDefaultValue("table"),
	),
	Fail:                components.NewBoolFlag(Fail, fmt.Sprintf("When using one of the flags --%s, --%s or --%s and a 'Fail build' rule is matched, the command will return exit code 3. Set to false if you'd like to see violations with exit code 0.", Watches, Project, RepoPath), components.WithBoolDefaultValue(true)),
	ExtendedTable:       components.NewBoolFlag(ExtendedTable, "Set to true if you'd like the table to include extended fields such as 'CVSS' & 'Xray Issue Id'. Ignored if provided 'format' is not 'table'."),
	BypassArchiveLimits: components.NewBoolFlag(BypassArchiveLimits, "Set to true to bypass the indexer-app archive limits."),
	MinSeverity:         components.NewStringFlag(MinSeverity, "Set the minimum severity of issues to display. The following values are accepted: Low, Medium, High or Critical."),
	FixableOnly:         components.NewBoolFlag(FixableOnly, "Set to true if you wish to display issues that have a fixed version only."),
	Rescan:              components.NewBoolFlag(Rescan, "Set to true when scanning an already successfully scanned build, for example after adding an ignore rule."),
	Vuln:                components.NewBoolFlag(Vuln, "Set to true if you'd like to receive an additional view of all vulnerabilities, regardless of the policy configured in Xray. Ignored if provided 'format' is 'sarif'."),
	InsecureTls:         components.NewBoolFlag(InsecureTls, "Set to true to skip TLS certificates verification."),
	ExcludeTestDeps:     components.NewBoolFlag(ExcludeTestDeps, "[Gradle] Set to true if you'd like to exclude Gradle test dependencies from Xray scanning."),
	useWrapperAudit: components.NewBoolFlag(
		UseWrapper,
		"Set to false if you wish to not use the gradle or maven wrapper.",
		components.WithBoolDefaultValue(true),
	),
	WorkingDirs: components.NewStringFlag(WorkingDirs, "A comma-separated list of relative working directories, to determine audit targets locations."),
	ExclusionsAudit: components.NewStringFlag(
		Exclusions,
		"List of exclusions separated by semicolons, utilized to skip sub-projects from undergoing an audit. These exclusions may incorporate the * and ? wildcards.",
		components.WithStrDefaultValue(strings.Join(utils.DefaultScaExcludePatterns, ";")),
	),
	Mvn:     components.NewBoolFlag(Mvn, "Set to true to request audit for a Maven project."),
	Gradle:  components.NewBoolFlag(Gradle, "Set to true to request audit for a Gradle project."),
	Npm:     components.NewBoolFlag(Npm, "Set to true to request audit for a npm project."),
	Pnpm:    components.NewBoolFlag(Pnpm, "Set to true to request audit for a Pnpm project."),
	Yarn:    components.NewBoolFlag(Yarn, "Set to true to request audit for a Yarn project."),
	Nuget:   components.NewBoolFlag(Nuget, "Set to true to request audit for a .NET project."),
	Pip:     components.NewBoolFlag(Pip, "Set to true to request audit for a Pip project."),
	Pipenv:  components.NewBoolFlag(Pipenv, "Set to true to request audit for a Pipenv project."),
	Poetry:  components.NewBoolFlag(Poetry, "Set to true to request audit for a Poetry project."),
	Go:      components.NewBoolFlag(Go, "Set to true to request audit for a Go project."),
	DepType: components.NewStringFlag(DepType, "[npm] Defines npm dependencies type. Possible values are: all, devOnly and prodOnly."),
	ThirdPartyContextualAnalysis: components.NewBoolFlag(
		ThirdPartyContextualAnalysis,
		"[npm] when set, the Contextual Analysis scan also uses the code of the project dependencies to determine the applicability of the vulnerability.",
		components.SetHiddenBoolFlag(),
	),
	RequirementsFile: components.NewStringFlag(RequirementsFile, "[Pip] Defines pip requirements file name. For example: 'requirements.txt'."),
	CurationOutput:   components.NewStringFlag(OutputFormat, "Defines the output format of the command. Acceptable values are: table, json.", components.WithStrDefaultValue("table")),
	Sca:              components.NewBoolFlag(Sca, fmt.Sprintf("Selective scanners mode: Execute SCA (Software Composition Analysis) sub-scan. By default, runs both SCA and Contextual Analysis. Can be combined with --%s, --%s, --%s, and --%s.", Secrets, Sast, Iac, WithoutCA)),
	Iac:              components.NewBoolFlag(Iac, fmt.Sprintf("Selective scanners mode: Execute IaC sub-scan. Can be combined with --%s, --%s and --%s.", Sca, Secrets, Sast)),
	Sast:             components.NewBoolFlag(Sast, fmt.Sprintf("Selective scanners mode: Execute SAST sub-scan. Can be combined with --%s, --%s and --%s.", Sca, Secrets, Iac)),
	Secrets:          components.NewBoolFlag(Secrets, fmt.Sprintf("Selective scanners mode: Execute Secrets sub-scan. Can be combined with --%s, --%s and --%s.", Sca, Sast, Iac)),
	WithoutCA:        components.NewBoolFlag(WithoutCA, fmt.Sprintf("Selective scanners mode: Disable Contextual Analysis scanner after SCA. Relevant only with --%s flag.", Sca)),

	// Git flags
	ScmType:         components.NewStringFlag(ScmType, fmt.Sprintf("SCM type. Possible values are: %s.", git.NewScmType().GetValidScmTypeString()), components.SetMandatory()),
	ScmApiUrl:       components.NewStringFlag(ScmApiUrl, "SCM API URL. For example: 'https://api.github.com'.", components.SetMandatory()),
	Token:           components.NewStringFlag(Token, fmt.Sprintf("SCM API token. In the absence of a flag, tokens should be passed in the %s enviroment variable, or in the corresponding environment variables '%s'.", git.GenericGitTokenEnvVar, git.NewScmType().GetOptionalScmTypeTokenEnvVars())),
	Owner:           components.NewStringFlag(Owner, "The owner of the repository. Depends on the git provider - on github and gitlab the owner is usually an individual or an organization, on bitbucket it is a project.", components.SetMandatory()),
	RepoName:        components.NewStringFlag(RepoName, "Specific repository name to analyze, If not provided all repositories in the project will be analyzed."),
	Months:          components.NewStringFlag(Months, "Number of months to analyze.", components.WithIntDefaultValue(git.DefaultContContributorsMonths)),
	DetailedSummary: components.NewBoolFlag(DetailedSummary, "Set to true to get a contributors detailed summary."),
}

func GetCommandFlags(cmdKey string) []components.Flag {
	return pluginsCommon.GetCommandFlags(cmdKey, commandFlags, flagsMap)
}
