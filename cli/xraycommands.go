package cli

import (
	"time"

	corecommon "github.com/jfrog/jfrog-cli-core/v2/common/commands"
	pluginsCommon "github.com/jfrog/jfrog-cli-core/v2/plugins/common"
	"github.com/jfrog/jfrog-cli-core/v2/plugins/components"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"

	"github.com/jfrog/jfrog-cli-security/commands/xray/curl"
	"github.com/jfrog/jfrog-cli-security/commands/xray/offlineupdate"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"

	flags "github.com/jfrog/jfrog-cli-security/cli/docs"
	auditSpecificDocs "github.com/jfrog/jfrog-cli-security/cli/docs/auditspecific"
	scanDocs "github.com/jfrog/jfrog-cli-security/cli/docs/scan/scan"
	curlDocs "github.com/jfrog/jfrog-cli-security/cli/docs/xray/curl"
	offlineupdateDocs "github.com/jfrog/jfrog-cli-security/cli/docs/xray/offlineupdate"
)

func getXrayNameSpaceCommands() []components.Command {
	return []components.Command{
		{
			Name:            "curl",
			Aliases:         []string{"cl"},
			Flags:           flags.GetCommandFlags(flags.XrCurl),
			Description:     curlDocs.GetDescription(),
			Arguments:       curlDocs.GetArguments(),
			SkipFlagParsing: true,
			Action:          curlCmd,
		},
		{
			Name:        "offline-update",
			Aliases:     []string{"ou"},
			Flags:       flags.GetCommandFlags(flags.OfflineUpdate),
			Description: offlineupdateDocs.GetDescription(),
			Action:      offlineUpdates,
		},

		// TODO: Deprecated commands (remove at next CLI major version)
		{
			Name:        "scan",
			Hidden:      true,
			Aliases:     []string{"s"},
			Flags:       flags.GetCommandFlags(flags.XrScan),
			Description: scanDocs.GetDescription(),
			Arguments:   scanDocs.GetArguments(),
			Action: func(c *components.Context) error {
				return pluginsCommon.RunCmdWithDeprecationWarning("scan", "xr", c, ScanCmd)
			},
		},
		{
			Name:        "audit-mvn",
			Hidden:      true,
			Aliases:     []string{"am"},
			Flags:       flags.GetCommandFlags(flags.AuditMvn),
			Description: auditSpecificDocs.GetMvnDescription(),
			Action: func(c *components.Context) error {
				return AuditSpecificCmd(c, techutils.Maven)
			},
		},
		{
			Name:        "audit-gradle",
			Hidden:      true,
			Aliases:     []string{"ag"},
			Flags:       flags.GetCommandFlags(flags.AuditGradle),
			Description: auditSpecificDocs.GetGradleDescription(),
			Action: func(c *components.Context) error {
				return AuditSpecificCmd(c, techutils.Gradle)
			},
		},
		{
			Name:        "audit-npm",
			Hidden:      true,
			Aliases:     []string{"an"},
			Flags:       flags.GetCommandFlags(flags.AuditNpm),
			Description: auditSpecificDocs.GetNpmDescription(),
			Action: func(c *components.Context) error {
				return AuditSpecificCmd(c, techutils.Npm)
			},
		},
		{
			Name:        "audit-go",
			Hidden:      true,
			Aliases:     []string{"ago"},
			Flags:       flags.GetCommandFlags(flags.AuditGo),
			Description: auditSpecificDocs.GetGoDescription(),
			Action: func(c *components.Context) error {
				return AuditSpecificCmd(c, techutils.Go)
			},
		},
		{
			Name:        "audit-pip",
			Hidden:      true,
			Aliases:     []string{"ap"},
			Flags:       flags.GetCommandFlags(flags.AuditPip),
			Description: auditSpecificDocs.GetPipDescription(),
			Action: func(c *components.Context) error {
				return AuditSpecificCmd(c, techutils.Pip)
			},
		},
	}
}

// Base on a given context from the CLI, create the curl command and execute it.
func curlCmd(c *components.Context) error {
	// Parse context and validate it for the command.
	if show, err := pluginsCommon.ShowCmdHelpIfNeeded(c, c.Arguments); show || err != nil {
		return err
	}
	if len(c.Arguments) < 1 {
		return pluginsCommon.WrongNumberOfArgumentsHandler(c)
	}
	// Create and execute the curl command.
	xrCurlCmd, err := newXrCurlCommand(c)
	if err != nil {
		return err
	}
	return corecommon.Exec(xrCurlCmd)
}

func newXrCurlCommand(c *components.Context) (*curl.XrCurlCommand, error) {
	xrCurlCommand := curl.NewXrCurlCommand(*corecommon.NewCurlCommand().SetArguments(pluginsCommon.ExtractArguments(c)))
	xrDetails, err := xrCurlCommand.GetServerDetails()
	if err != nil {
		return nil, err
	}
	if xrDetails.XrayUrl == "" {
		return nil, errorutils.CheckErrorf("No Xray servers configured. Use the 'jf c add' command to set the Xray server details.")
	}
	xrCurlCommand.SetServerDetails(xrDetails)
	xrCurlCommand.SetUrl(xrDetails.XrayUrl)
	return xrCurlCommand, err
}

// Base on a given context from the CLI, create the offline-update command and execute it.
func offlineUpdates(c *components.Context) error {
	offlineUpdateFlags, err := getOfflineUpdatesFlag(c)
	if err != nil {
		return err
	}
	return offlineupdate.OfflineUpdate(offlineUpdateFlags)
}

func getOfflineUpdatesFlag(c *components.Context) (offlineFlags *offlineupdate.OfflineUpdatesFlags, err error) {
	offlineFlags = new(offlineupdate.OfflineUpdatesFlags)
	offlineFlags.License = c.GetStringFlagValue(flags.LicenseId)
	if len(offlineFlags.License) < 1 {
		return nil, errorutils.CheckErrorf("the --%s option is mandatory", flags.LicenseId)
	}
	offlineFlags.Version = c.GetStringFlagValue(flags.Version)
	offlineFlags.Target = c.GetStringFlagValue(flags.Target)
	// Handle V3 flags
	stream := c.GetStringFlagValue(flags.Stream)
	offlineFlags.IsPeriodicUpdate = c.GetBoolFlagValue(flags.Periodic)
	// If a 'stream' flag was provided - validate its value and return.
	if stream != "" {
		offlineFlags.Stream, err = offlineupdate.ValidateStream(stream)
		return
	}
	if offlineFlags.IsPeriodicUpdate {
		return nil, errorutils.CheckErrorf("the %s option is only valid with %s", flags.Periodic, flags.Stream)
	}
	// Handle V1 flags
	from := c.GetStringFlagValue(flags.From)
	to := c.GetStringFlagValue(flags.To)
	if len(to) > 0 && len(from) < 1 {
		return nil, errorutils.CheckErrorf("the --%s option is mandatory, when the --%s option is sent", flags.From, flags.To)
	}
	if len(from) > 0 && len(to) < 1 {
		return nil, errorutils.CheckErrorf("the --%s option is mandatory, when the --%s option is sent", flags.To, flags.From)
	}
	if len(from) > 0 && len(to) > 0 {
		offlineFlags.From, err = dateToMilliseconds(from)
		err = errorutils.CheckError(err)
		if err != nil {
			return
		}
		offlineFlags.To, err = dateToMilliseconds(to)
		err = errorutils.CheckError(err)
	}
	return
}

func dateToMilliseconds(date string) (dateInMillisecond int64, err error) {
	dateFormat := "2006-01-02"
	t, err := time.Parse(dateFormat, date)
	if errorutils.CheckError(err) != nil {
		return
	}
	dateInMillisecond = t.UnixNano() / (int64(time.Millisecond) / int64(time.Nanosecond))
	return
}
