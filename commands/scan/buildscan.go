package scan

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/jfrog/jfrog-cli-core/v2/common/build"
	outputFormat "github.com/jfrog/jfrog-cli-core/v2/common/format"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/results/output"
	xrayutils "github.com/jfrog/jfrog-cli-security/utils/xray"
	clientutils "github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray"
	"github.com/jfrog/jfrog-client-go/xray/services"
)

const (
	BuildScanMinVersion                       = "3.37.0"
	BuildScanIncludeVulnerabilitiesMinVersion = "3.40.0"
)

type BuildScanCommand struct {
	serverDetails          *config.ServerDetails
	outputFormat           outputFormat.OutputFormat
	buildConfiguration     *build.BuildConfiguration
	includeVulnerabilities bool
	failBuild              bool
	printExtendedTable     bool
	rescan                 bool
}

func NewBuildScanCommand() *BuildScanCommand {
	return &BuildScanCommand{}
}

func (bsc *BuildScanCommand) SetServerDetails(server *config.ServerDetails) *BuildScanCommand {
	bsc.serverDetails = server
	return bsc
}

func (bsc *BuildScanCommand) SetOutputFormat(format outputFormat.OutputFormat) *BuildScanCommand {
	bsc.outputFormat = format
	return bsc
}

func (bsc *BuildScanCommand) ServerDetails() (*config.ServerDetails, error) {
	return bsc.serverDetails, nil
}

func (bsc *BuildScanCommand) SetBuildConfiguration(buildConfiguration *build.BuildConfiguration) *BuildScanCommand {
	bsc.buildConfiguration = buildConfiguration
	return bsc
}

func (bsc *BuildScanCommand) SetIncludeVulnerabilities(include bool) *BuildScanCommand {
	bsc.includeVulnerabilities = include
	return bsc
}

func (bsc *BuildScanCommand) SetFailBuild(failBuild bool) *BuildScanCommand {
	bsc.failBuild = failBuild
	return bsc
}

func (bsc *BuildScanCommand) SetPrintExtendedTable(printExtendedTable bool) *BuildScanCommand {
	bsc.printExtendedTable = printExtendedTable
	return bsc
}

func (bsc *BuildScanCommand) SetRescan(rescan bool) *BuildScanCommand {
	bsc.rescan = rescan
	return bsc
}

// Scan published builds with Xray
func (bsc *BuildScanCommand) Run() (err error) {
	xrayManager, xrayVersion, err := xrayutils.CreateXrayServiceManagerAndGetVersion(bsc.serverDetails)
	if err != nil {
		return err
	}
	err = clientutils.ValidateMinimumVersion(clientutils.Xray, xrayVersion, BuildScanMinVersion)
	if err != nil {
		return err
	}
	if bsc.includeVulnerabilities {
		err = clientutils.ValidateMinimumVersion(clientutils.Xray, xrayVersion, BuildScanIncludeVulnerabilitiesMinVersion)
		if err != nil {
			return errors.New("build-scan command with '--vuln' flag is not supported on your current Xray version. " + err.Error())
		}
	}
	buildName, err := bsc.buildConfiguration.GetBuildName()
	if err != nil {
		return err
	}
	buildNumber, err := bsc.buildConfiguration.GetBuildNumber()
	if err != nil {
		return err
	}
	params := services.XrayBuildParams{
		BuildName:   buildName,
		BuildNumber: buildNumber,
		Project:     bsc.buildConfiguration.GetProject(),
		Rescan:      bsc.rescan,
	}

	isFailBuildResponse, err := bsc.runBuildScanAndPrintResults(xrayManager, xrayVersion, params)
	if err != nil {
		return err
	}
	// If failBuild flag is true and also got fail build response from Xray
	if bsc.failBuild && isFailBuildResponse {
		return results.NewFailBuildError()
	}
	return
}

func (bsc *BuildScanCommand) runBuildScanAndPrintResults(xrayManager *xray.XrayServicesManager, xrayVersion string, params services.XrayBuildParams) (isFailBuildResponse bool, err error) {
	buildScanResults, noFailBuildPolicy, err := xrayManager.BuildScan(params, bsc.includeVulnerabilities)
	if err != nil {
		return false, err
	}

	// A patch for Xray issue where it returns Base URL from the API but it is sometimes not the URL that is configured in the CLI
	// More info in https://jfrog-int.atlassian.net/browse/XRAY-77451

	url, endpoint, trimerr := trimUrl(buildScanResults.MoreDetailsUrl)
	if trimerr != nil {
		return false, err
	}
	cliUrl, err := getActualUrl(*bsc.serverDetails)
	if err != nil {
		return false, err
	}
	// Check that the response url from scan build API is the same url as the one that was inserted to the CLI in config
	if url != cliUrl {
		// if URL from XRAY API is different than the URL in CLI config change the printed url to the CLI config URL and the endpoint from API
		log.Debug(fmt.Sprintf("The resulted url from API is %s, and the CLI config url is %s", url, cliUrl))
		buildScanResults.MoreDetailsUrl = cliUrl + endpoint
	}
	log.Info("The scan data is available at: " + buildScanResults.MoreDetailsUrl)
	isFailBuildResponse = buildScanResults.FailBuild

	cmdResults := results.NewCommandResults(utils.Build).SetXrayVersion(xrayVersion)
	scanResults := cmdResults.NewScanResults(results.ScanTarget{Name: fmt.Sprintf("%s (%s)", params.BuildName, params.BuildNumber)})
	scanResults.NewScaScanResults(services.ScanResponse{
		Violations:      buildScanResults.Violations,
		Vulnerabilities: buildScanResults.Vulnerabilities,
		XrayDataUrl:     buildScanResults.MoreDetailsUrl,
	})

	resultsPrinter := output.NewResultsWriter(cmdResults).
		SetOutputFormat(bsc.outputFormat).
		SetHasViolationContext(true).
		SetIncludeVulnerabilities(bsc.includeVulnerabilities).
		SetIncludeLicenses(false).
		SetIsMultipleRootProject(true).
		SetPrintExtendedTable(bsc.printExtendedTable)

	if bsc.outputFormat != outputFormat.Table {
		// Print the violations and/or vulnerabilities as part of one JSON.
		if err = resultsPrinter.PrintScanResults(); err != nil {
			return
		}
	} else {
		// Print two different tables for violations and vulnerabilities (if needed)

		// If "No Xray Fail build policy...." error received, no need to print violations
		if !noFailBuildPolicy {
			if err = resultsPrinter.PrintScanResults(); err != nil {
				return false, err
			}
		}
	}
	err = bsc.recordResults(cmdResults, params)
	return
}

func (bsc *BuildScanCommand) recordResults(cmdResults *results.SecurityCommandResults, params services.XrayBuildParams) (err error) {
	var summary output.ScanCommandResultSummary
	if summary, err = output.NewBuildScanSummary(
		cmdResults,
		bsc.serverDetails,
		bsc.includeVulnerabilities,
		params.BuildName, params.BuildNumber,
	); err != nil {
		return
	}
	return output.RecordSecurityCommandSummary(summary)
}

func (bsc *BuildScanCommand) CommandName() string {
	return "xr_build_scan"
}

// There are two cases. when serverDetails.Url is configured and when serverDetails.XrayUrl and serverDetails.ArtifactoryUrl are configured
// The function will return the Url if configured and will trim xray if serverDetails.Url is not configured
func getActualUrl(serverDetails config.ServerDetails) (string, error) {
	url, _, err := trimUrl(serverDetails.Url)
	if err != nil {
		return "", err
	}
	if url != "" {
		return url, nil
	}

	url, _, trimerr := trimUrl(serverDetails.XrayUrl)
	return url, trimerr
}

// trim URL to be http(s)://<JFROG-URL> and the endpoint
// return the base url the endpoint and an error if the parsing failed
func trimUrl(fullUrl string) (string, string, error) {
	if fullUrl == "" {
		return "", "", nil
	}
	// Parse through the url and endpoint
	parsedUrl, err := url.Parse(fullUrl)
	if err != nil {
		return "", "", err
	}

	// Separate to BaseUrl http(s)://<JFROG-URL> and endpoint of the API request
	baseUrl := fmt.Sprintf("%s://%s/", parsedUrl.Scheme, parsedUrl.Host)
	endpoint := strings.TrimPrefix(fullUrl, baseUrl)

	return baseUrl, endpoint, nil
}
