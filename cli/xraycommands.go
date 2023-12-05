package cli

import (
	"time"

	corecommon "github.com/jfrog/jfrog-cli-core/v2/common/commands"
	"github.com/jfrog/jfrog-cli-core/v2/plugins/components"
	"github.com/jfrog/jfrog-cli-core/v2/utils/cliutils"
	"github.com/jfrog/jfrog-client-go/utils/errorutils"

	"github.com/jfrog/jfrog-cli-security/commands/curl"
	"github.com/jfrog/jfrog-cli-security/commands/offlineupdate"
)

func GetXrayNameSpaceCommands() []components.Command {
	return []components.Command{
		{
			Name:            "curl",
			Aliases:         []string{"cl"},
			Flags:           GetCommandFlags(XrCurl),
			Description:     curl.GetDescription(),
			Arguments:       curl.GetArguments(),
			SkipFlagParsing: true,
			Action:          curlCmd,
		},
		{
			Name:        "offline-update",
			Aliases:     []string{"ou"},
			Flags:       GetCommandFlags(OfflineUpdate),
			Description: offlineupdate.GetDescription(),
			// Usage: offlineupdate.Usage,
			HelpName:    corecommondocs.CreateUsage("xr offline-update", offlineupdatedocs.GetDescription(), offlineupdatedocs.Usage),
			Action:      offlineUpdates,
		},
		
		// TODO: Deprecated commands (remove at next CLI major version)
		{
			Name:         "scan",
			Aliases:      []string{"s"},
			Flags:        GetCommandFlags(XrScan),
			Description:  scandocs.GetDescription(),
			Arguments:    scandocs.GetArguments(),
			HelpName:     corecommondocs.CreateUsage("xr scan", scandocs.GetDescription(), scandocs.Usage),
			Action: func(c *components.Context) error {
				return cliutils.RunCmdWithDeprecationWarning("scan", "xr", c, scan.ScanCmd)
			},
		},
	}
}

// Base on a given context from the CLI, create the curl command and execute it.
func curlCmd(c *components.Context) error {
	// Parse context and validate it for the command.
	if show, err := cliutils.ShowCmdHelpIfNeeded(c, c.Arguments); show || err != nil {
		return err
	}
	if len(c.Arguments) < 1 {
		return cliutils.WrongNumberOfArgumentsHandler(c)
	}
	// Create and execute the curl command.
	xrCurlCmd, err := newXrCurlCommand(c)
	if err != nil {
		return err
	}
	return corecommon.Exec(xrCurlCmd)
}

func newXrCurlCommand(c *components.Context) (*curl.XrCurlCommand, error) {
	xrCurlCommand := curl.NewXrCurlCommand(*corecommon.NewCurlCommand().SetArguments(cliutils.ExtractArguments(c)))
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
	offlineFlags.License = c.GetStringFlagValue(LicenseId)
	if len(offlineFlags.License) < 1 {
		return nil, errorutils.CheckErrorf("the --%s option is mandatory", LicenseId)
	}
	offlineFlags.Version = c.GetStringFlagValue(Version)
	offlineFlags.Target = c.GetStringFlagValue(Target)
	// Handle V3 flags
	stream := c.GetStringFlagValue(Stream)
	offlineFlags.IsPeriodicUpdate = c.GetBoolFlagValue(Periodic)
	// If a 'stream' flag was provided - validate its value and return.
	if stream != "" {
		offlineFlags.Stream, err = validateStream(stream)
		return
	}
	if offlineFlags.IsPeriodicUpdate {
		return nil, errorutils.CheckErrorf("the %s option is only valid with %s", Periodic, Stream)
	}
	// Handle V1 flags
	from := c.GetStringFlagValue(From)
	to := c.GetStringFlagValue(To)
	if len(to) > 0 && len(from) < 1 {
		return nil, errorutils.CheckErrorf("the --%s option is mandatory, when the --%s option is sent", From, To)
	}
	if len(from) > 0 && len(to) < 1 {
		return nil, errorutils.CheckErrorf("the --%s option is mandatory, when the --%s option is sent", To, From)
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

// Verify that the given string is a valid optional stream.
func validateStream(stream string) (string, error) {
	streams := offlineupdate.NewValidStreams()
	if streams.StreamsMap[stream] {
		return stream, nil
	}
	return "", errorutils.CheckErrorf("Invalid stream type: %s, Possible values are: %v", stream, streams.GetValidStreamsString())
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