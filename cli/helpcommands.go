package cli

import (
	"fmt"
	"sort"

	corecommon "github.com/jfrog/jfrog-cli-core/v2/docs/common"
	flags "github.com/jfrog/jfrog-cli-security/cli/docs"
	dockerScanDocs "github.com/jfrog/jfrog-cli-security/cli/docs/scan/dockerscan"
	"github.com/jfrog/jfrog-client-go/utils/log"
	cliCommand "github.com/urfave/cli"
)

const (
	// Security Commands Keys
	Dockerscan = "dockerscanhelp"

	// Indexer Flags
	BypassArchiveLimits = "bypass-archive-limits"

	// Output Data Flags
	OutputFormat    = "format"
	DetailedSummary = "detailed-summary"
	FixableOnly     = "fixable-only"
	MinSeverity     = "min-severity"
	ExtendedTable   = "extended-table"

	// Security Flags
	Fail        = "fail"
	Watches     = "watches"
	RepoPath    = "repo-path"
	Vuln        = "vuln"
	scanPrefix  = "scan-"
	buildPrefix = "build-"
	BuildVuln   = buildPrefix + Vuln
	ScanVuln    = scanPrefix + Vuln
	Licenses    = "licenses"

	// JAS Flags
	Sca              = "sca"
	Iac              = "iac"
	Sast             = "sast"
	Secrets          = "secrets"
	WithoutCA        = "without-contextual-analysis"
	SecretValidation = "secret-validation"

	// General Flags
	Project  = "project"
	ServerId = "server-id"
)

var flagsMap = map[string]cliCommand.Flag{
	// Common commands flags
	ServerId: cliCommand.StringFlag{
		Name:  ServerId,
		Usage: "[Optional] Server ID configured using the config command.",
	},
	// Scan flags
	Watches: cliCommand.StringFlag{
		Name:  Watches,
		Usage: "[Optional] A comma-separated(,) list of Xray watches, to determine Xray's violations creation.` `",
	},
	MinSeverity: cliCommand.StringFlag{
		Name:  MinSeverity,
		Usage: "[Optional] Set the minimum severity of issues to display. The following values are accepted: Low, Medium, High or Critical.` `",
	},
	FixableOnly: cliCommand.BoolFlag{
		Name:  FixableOnly,
		Usage: "[Optional] Set to true if you wish to display issues that have a fixed version only.` `",
	},
	ExtendedTable: cliCommand.BoolFlag{
		Name:  ExtendedTable,
		Usage: "[Optional] Set to true if you'd like the table to include extended fields such as 'CVSS' & 'Xray Issue Id'. Ignored if provided 'format' is not 'table'.",
	},
	BypassArchiveLimits: cliCommand.BoolFlag{
		Name:  BypassArchiveLimits,
		Usage: "[Optional] Set to true to bypass the indexer-app archive limits.",
	},
	Project: cliCommand.StringFlag{
		Name:  Project,
		Usage: "[Optional] JFrog Artifactory project key.",
	},
	RepoPath: cliCommand.StringFlag{
		Name:  RepoPath,
		Usage: "[Optional] Target repo path, to enable Xray to determine watches accordingly.",
	},
	Licenses: cliCommand.BoolFlag{
		Name:  Licenses,
		Usage: "[Optional] Set to true if you'd like to receive licenses from Xray scanning.",
	},
	Fail: cliCommand.BoolFlag{
		Name:  Fail,
		Usage: fmt.Sprintf("[Optional] When using one of the flags --%s, --%s or --%s and a 'Fail build' rule is matched, the command will return exit code 3. Set to false if you'd like to see violations with exit code 0.", Watches, Project, RepoPath),
	},
	OutputFormat: cliCommand.StringFlag{
		Name:  OutputFormat,
		Usage: "Defines the output format of the command. Acceptable values are: table, json, simple-json and sarif. Note: the json format doesn't include information about scans that are included as part of the Advanced Security package.",
	},
	// JAS Flags
	Sca: cliCommand.BoolFlag{
		Name:  Sca,
		Usage: fmt.Sprintf("Selective scanners mode: Execute SCA (Software Composition Analysis) sub-scan. By default, runs both SCA and Contextual Analysis. Can be combined with --%s, --%s, --%s, and --%s.", Secrets, Sast, Iac, WithoutCA),
	},
	Iac: cliCommand.BoolFlag{
		Name:  Iac,
		Usage: fmt.Sprintf("Selective scanners mode: Execute IaC sub-scan. Can be combined with --%s, --%s and --%s.", Sca, Secrets, Sast),
	},
	Sast: cliCommand.BoolFlag{
		Name:  Sast,
		Usage: fmt.Sprintf("Selective scanners mode: Execute SAST sub-scan. Can be combined with --%s, --%s and --%s.", Sca, Secrets, Iac),
	},
	Secrets: cliCommand.BoolFlag{
		Name:  Secrets,
		Usage: fmt.Sprintf("Selective scanners mode: Execute Secrets sub-scan. Can be combined with --%s, --%s and --%s.", Sca, Sast, Iac),
	},
	WithoutCA: cliCommand.BoolFlag{
		Name:  WithoutCA,
		Usage: fmt.Sprintf("Selective scanners mode: Disable Contextual Analysis scanner after SCA. Relevant only with --%s flag.", Sca),
	},
	SecretValidation: cliCommand.BoolFlag{
		Name:  SecretValidation,
		Usage: fmt.Sprintf("Selective scanners mode: Execute Token validation sub-scan on secrets. Relevant only with --%s flag.", Secrets),
	},
	// Git Flags
	DetailedSummary: cliCommand.BoolFlag{
		Name:  DetailedSummary,
		Usage: "[Optional] Set to true to get a contributors detailed summary.",
	},
}

var commandFlags = map[string][]string{
	Dockerscan: {
		BypassArchiveLimits, DetailedSummary, ExtendedTable, Fail,
		FixableOnly, OutputFormat, Licenses, MinSeverity, Project, RepoPath,
		ServerId, Vuln, Watches, Secrets, SecretValidation,
	},
}

func GetSecurityHelpCommands() []cliCommand.Command {
	return []cliCommand.Command{
		{
			// this command is hidden and have no logic, it will be run to provide 'help' as a part of the buildtools CLI for 'docker' commands. ('jf docker scan')
			// CLI buildtools will run the command if requested: https://github.com/jfrog/jfrog-cli/blob/v2/buildtools/cli.go
			Name:      dockerScanCmdHiddenName,
			Flags:     GetCommandFlags(flags.DockerScan),
			Usage:     dockerScanDocs.GetDescription(),
			HelpName:  corecommon.CreateUsage("docker scan", dockerScanDocs.GetDescription(), dockerScanDocs.Usage),
			UsageText: dockerScanDocs.GetArguments(),
			ArgsUsage: dockerScanDocs.GetArguments(),
			Hidden:    true,
		},
	}
}

func GetCommandFlags(cmd string) []cliCommand.Flag {
	flagList, ok := commandFlags[cmd]
	if !ok {
		log.Error("The command \"", cmd, "\" is not found in commands flags map.")
		return nil
	}
	return buildAndSortFlags(flagList)
}

func buildAndSortFlags(keys []string) (flags []cliCommand.Flag) {
	for _, flag := range keys {
		flags = append(flags, flagsMap[flag])
	}
	sort.Slice(flags, func(i, j int) bool { return flags[i].GetName() < flags[j].GetName() })
	return
}
