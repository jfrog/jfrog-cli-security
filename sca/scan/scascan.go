package scan

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/CycloneDX/cyclonedx-go"

	"github.com/jfrog/gofrog/parallel"
	clientUtils "github.com/jfrog/jfrog-client-go/utils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/jfrog/jfrog-client-go/xray/services"
	xscServices "github.com/jfrog/jfrog-client-go/xsc/services"

	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats/cdxutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
)

// SbomScanStrategy is an interface for scanning SBOMs using different strategies.
type SbomScanStrategy interface {
	// WithOptions allows to set options for the SBOM scan strategy.
	WithOptions(options ...SbomScanOption) SbomScanStrategy
	// PrepareStrategy prepares the strategy for SBOM scanning, should be called once before scanning SBOMs.
	PrepareStrategy() error
	// DeprecatedScanTask scans the given SBOM using the specified technology returning the scan response.
	// TODO: This method is deprecated and only used for backward compatibility until the new BOM can contain all the information scanResponse contains.
	// Missing attributes:
	// - ExtendedInformation (JfrogResearchInformation): ShortDescription, FullDescription, frogResearchSeverityReasons, Remediation
	DeprecatedScanTask(target *cyclonedx.BOM) (services.ScanResponse, error)
	// Perform a Scan on the given SBOM and return the enriched CycloneDX BOM and calculated violations. (Violations will be moved at the future to the end of command)
	SbomEnrichTask(target *cyclonedx.BOM) (*cyclonedx.BOM, []services.Violation, error)
}

type SbomScanOption func(sss SbomScanStrategy)

type ScaScanParams struct {
	// The TargetResults contains the Sbom target for scan.
	ScanResults *results.TargetResults
	// Params to decide if the scan should be performed.
	ScansToPerform []utils.SubScanType
	ConfigProfile  *xscServices.ConfigProfile
	// If true and error occur, the error will not end the scan.
	AllowPartialResults bool
	// If provided, the raw scan results will be saved to this directory.
	ResultsOutputDir string
	// For Source-Code (Audit), scans are performed in parallel, thus we need to pass the security parallel runner.
	Runner   *utils.SecurityParallelRunner
	ThreadId int
	// TODO: remove this field once the new flow is fully implemented.
	IsNewFlow bool
}

func RunScaScan(strategy SbomScanStrategy, params ScaScanParams) (generalError error) {
	shouldRunScan, generalError := shouldRunScan(params)
	if generalError != nil || !shouldRunScan {
		return
	}
	if params.Runner != nil {
		return runScaScanWithRunner(strategy, params)
	}
	// Scan target
	if taskErr := scaScanTask(strategy, params); taskErr != nil {
		return params.ScanResults.AddTargetError(fmt.Errorf("failed to execute SCA scan: %s", taskErr.Error()), params.AllowPartialResults)
	}
	return
}

// For Audit scans, we run the scan in parallel using the SecurityParallelRunner.
func runScaScanWithRunner(strategy SbomScanStrategy, params ScaScanParams) (generalError error) {
	targetResult := params.ScanResults
	// Create sca scan task
	if _, taskCreationErr := params.Runner.Runner.AddTaskWithError(createScaScanTaskWithRunner(params.Runner, strategy, params), func(err error) {
		_ = targetResult.AddTargetError(fmt.Errorf("failed to execute SCA scan: %s", err.Error()), params.AllowPartialResults)
	}); taskCreationErr != nil {
		_ = targetResult.AddTargetError(fmt.Errorf("failed to create SCA scan task: %s", taskCreationErr.Error()), params.AllowPartialResults)
		// If we failed to create the task, we need to mark it as done
		params.Runner.ScaScansWg.Done()
	}
	return nil
}

// For Audit scans, we run the scan in parallel using the SecurityParallelRunner.
func createScaScanTaskWithRunner(auditParallelRunner *utils.SecurityParallelRunner, strategy SbomScanStrategy, params ScaScanParams) parallel.TaskFunc {
	auditParallelRunner.ScaScansWg.Add(1)
	return func(threadId int) (err error) {
		defer auditParallelRunner.ScaScansWg.Done()
		params.ThreadId = threadId
		auditParallelRunner.ResultsMu.Lock()
		defer auditParallelRunner.ResultsMu.Unlock()
		return scaScanTask(strategy, params)
	}
}

func shouldRunScan(params ScaScanParams) (bool, error) {
	logPrefix := ""
	if params.ThreadId >= 0 {
		logPrefix = clientUtils.GetLogMsgPrefix(params.ThreadId, false)
	}
	// If the scan is not requested, skip it.
	if len(params.ScansToPerform) > 0 && !slices.Contains(params.ScansToPerform, utils.ScaScan) {
		log.Debug(fmt.Sprintf("%sSkipping SCA for %s as requested by input...", logPrefix, params.ScanResults.Target))
		return false, nil
	}
	// If the scan is turned off in the config profile, skip it.
	if params.ConfigProfile != nil {
		if len(params.ConfigProfile.Modules) < 1 {
			// Verify Modules are not nil and contain at least one modules
			return false, fmt.Errorf("config profile %s has no modules. A config profile must contain at least one modules", params.ConfigProfile.ProfileName)
		}
		if !params.ConfigProfile.Modules[0].ScanConfig.ScaScannerConfig.EnableScaScan {
			log.Debug(fmt.Sprintf("%sSkipping SCA as requested by '%s' config profile...", logPrefix, params.ConfigProfile.ProfileName))
			return false, nil
		}
	}
	if params.ScanResults == nil {
		return false, errors.New("scan results are nil for target")
	}
	return hasDependenciesToScan(params.ScanResults, logPrefix), nil
}

func hasDependenciesToScan(targetResults *results.TargetResults, logPrefix string) bool {
	if targetResults == nil || targetResults.ScaResults == nil || targetResults.ScaResults.Sbom == nil || targetResults.ScaResults.Sbom.Components == nil {
		log.Debug(fmt.Sprintf("%sSkipping SCA for %s as no components were found in the target", logPrefix, targetResults.Target))
		return false
	}
	for _, root := range cdxutils.GetRootDependenciesEntries(targetResults.ScaResults.Sbom) {
		if root.Dependencies != nil && len(*root.Dependencies) > 0 {
			// Found at least one dependency, we can run the scan.
			return true
		}
	}
	log.Debug(fmt.Sprintf("%sSkipping SCA for %s as no dependencies were found in the target", logPrefix, targetResults.Target))
	return false
}

func scaScanTask(strategy SbomScanStrategy, params ScaScanParams) (err error) {
	logPrefix := ""
	if params.ThreadId >= 0 {
		logPrefix = clientUtils.GetLogMsgPrefix(params.ThreadId, false)
	}
	log.Info(logPrefix + fmt.Sprintf("Running SCA for %d components at %s", len(*params.ScanResults.ScaResults.Sbom.Components), params.ScanResults.String()))
	if !params.IsNewFlow {
		scanResults, err := strategy.DeprecatedScanTask(params.ScanResults.ScaResults.Sbom)
		// We add the results before checking for errors, so we can display the results even if an error occurred.
		params.ScanResults.ScaScanResults(GetScaScansStatusCode(err, scanResults), scanResults)
		if err != nil {
			return err
		}
		log.Info(logPrefix + utils.GetScanFindingsLog(utils.ScaScan, len(scanResults.Vulnerabilities), len(scanResults.Violations)))
		return dumpScanResponseToFileIfNeeded(scanResults, params.ResultsOutputDir, utils.ScaScan, params.ThreadId)
	}
	// New flow: we scan the SBOM and enrich it with CVE vulnerabilities and calculate violations.
	bomWithVulnerabilities, violations, err := strategy.SbomEnrichTask(params.ScanResults.ScaResults.Sbom)
	// We add the results before checking for errors, so we can display the results even if an error occurred.
	params.ScanResults.EnrichedSbomScanResults(GetScaScansStatusCode(err), bomWithVulnerabilities, violations...)
	if err != nil {
		return fmt.Errorf("failed to enrich SBOM for %s: %w", params.ScanResults.Target, err)
	}
	if params.ScanResults.ScaResults.Sbom.Vulnerabilities != nil {
		log.Info(logPrefix + utils.GetScanFindingsLog(utils.ScaScan, len(*params.ScanResults.ScaResults.Sbom.Vulnerabilities), len(violations)))
	}
	return dumpEnrichedCdxToFileIfNeeded(bomWithVulnerabilities, params.ResultsOutputDir, utils.ScaScan, params.ThreadId)
}

// Infer the status code of SCA Xray scan, if err occurred or any of the results is `failed` return 1, otherwise return 0.
func GetScaScansStatusCode(err error, results ...services.ScanResponse) int {
	if err != nil {
		return 1
	}
	for _, result := range results {
		if result.ScannedStatus == "failed" {
			return 1
		}
	}
	return 0
}

// If an output dir was provided through --output-dir flag, we create in the provided path new file containing the scan results
// TODO: remove this function once the new flow is fully implemented.
func dumpScanResponseToFileIfNeeded(results services.ScanResponse, scanResultsOutputDir string, scanType utils.SubScanType, threadId int) (err error) {
	if scanResultsOutputDir == "" {
		return
	}
	fileContent, err := json.Marshal(results)
	if err != nil {
		return fmt.Errorf("failed to write %s scan results to file: %s", scanType, err.Error())
	}
	return utils.DumpJsonContentToFile(fileContent, scanResultsOutputDir, scanType.String(), threadId)
}

// If an output dir was provided through --output-dir flag, we create in the provided path new file containing the scan results
func dumpEnrichedCdxToFileIfNeeded(content *cyclonedx.BOM, scanResultsOutputDir string, scanType utils.SubScanType, threadId int) (err error) {
	if scanResultsOutputDir == "" {
		return
	}
	return utils.DumpCdxContentToFile(content, scanResultsOutputDir, scanType.String(), threadId)
}
