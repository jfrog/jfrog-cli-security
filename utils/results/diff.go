package results

import (
	"path/filepath"
	"strings"

	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"
)

// UnifyScaAndJasResults merges SCA and JAS diff results into a single SecurityCommandResults.
func UnifyScaAndJasResults(scaResults, jasDiffResults *SecurityCommandResults) *SecurityCommandResults {
	gitContext := scaResults.GitContext
	if gitContext == nil {
		gitContext = jasDiffResults.GitContext
	}

	unifiedResults := &SecurityCommandResults{
		ResultsMetaData: ResultsMetaData{
			EntitledForJas:   jasDiffResults.EntitledForJas,
			SecretValidation: jasDiffResults.SecretValidation,
			CmdType:          jasDiffResults.CmdType,
			XrayVersion:      jasDiffResults.XrayVersion,
			XscVersion:       jasDiffResults.XscVersion,
			MultiScanId:      jasDiffResults.MultiScanId,
			StartTime:        jasDiffResults.StartTime,
			ResultContext:    jasDiffResults.ResultContext,
			GitContext:       gitContext,
		},
	}

	for _, scaTarget := range scaResults.Targets {
		var jasTarget *TargetResults
		for _, jTarget := range jasDiffResults.Targets {
			if jTarget.Target == scaTarget.Target {
				jasTarget = jTarget
				break
			}
		}

		unifiedTarget := &TargetResults{
			ScanTarget:       scaTarget.ScanTarget,
			AppsConfigModule: scaTarget.AppsConfigModule,
			ScaResults:       scaTarget.ScaResults,
			JasResults:       scaTarget.JasResults,
		}

		if jasTarget != nil && jasTarget.JasResults != nil {
			if unifiedTarget.JasResults == nil {
				unifiedTarget.JasResults = jasTarget.JasResults
			} else {
				unifiedTarget.JasResults.JasVulnerabilities.SecretsScanResults = jasTarget.JasResults.JasVulnerabilities.SecretsScanResults
				unifiedTarget.JasResults.JasVulnerabilities.IacScanResults = jasTarget.JasResults.JasVulnerabilities.IacScanResults
				unifiedTarget.JasResults.JasVulnerabilities.SastScanResults = jasTarget.JasResults.JasVulnerabilities.SastScanResults
				unifiedTarget.JasResults.JasViolations.SecretsScanResults = jasTarget.JasResults.JasViolations.SecretsScanResults
				unifiedTarget.JasResults.JasViolations.IacScanResults = jasTarget.JasResults.JasViolations.IacScanResults
				unifiedTarget.JasResults.JasViolations.SastScanResults = jasTarget.JasResults.JasViolations.SastScanResults
			}
		}

		unifiedResults.Targets = append(unifiedResults.Targets, unifiedTarget)
	}

	return unifiedResults
}

// CompareJasResults computes the diff between target and source JAS results.
// Returns only NEW findings in source that don't exist in target.
func CompareJasResults(targetResults, sourceResults *SecurityCommandResults) *SecurityCommandResults {
	log.Info("[DIFF] Starting JAS diff calculation")
	log.Debug("[DIFF] Comparing", len(sourceResults.Targets), "source targets against", len(targetResults.Targets), "target targets")

	diffResults := &SecurityCommandResults{
		ResultsMetaData: ResultsMetaData{
			EntitledForJas:   sourceResults.EntitledForJas,
			SecretValidation: sourceResults.SecretValidation,
			CmdType:          sourceResults.CmdType,
			XrayVersion:      sourceResults.XrayVersion,
			XscVersion:       sourceResults.XscVersion,
			MultiScanId:      sourceResults.MultiScanId,
			StartTime:        sourceResults.StartTime,
			ResultContext:    sourceResults.ResultContext,
		},
	}

	for _, sourceTarget := range sourceResults.Targets {
		if sourceTarget.JasResults == nil {
			continue
		}

		var allTargetJasResults []*JasScansResults
		for _, targetTarget := range targetResults.Targets {
			if targetTarget.JasResults != nil {
				allTargetJasResults = append(allTargetJasResults, targetTarget.JasResults)
			}
		}

		diffJasResults := filterExistingFindings(allTargetJasResults, sourceTarget.JasResults)

		diffTarget := &TargetResults{
			ScanTarget: sourceTarget.ScanTarget,
			JasResults: diffJasResults,
		}

		diffResults.Targets = append(diffResults.Targets, diffTarget)
	}

	return diffResults
}

// filterExistingFindings removes findings from source that already exist in target.
func filterExistingFindings(allTargetJasResults []*JasScansResults, sourceJasResults *JasScansResults) *JasScansResults {
	if sourceJasResults == nil {
		return nil
	}

	if len(allTargetJasResults) == 0 {
		return sourceJasResults
	}

	targetKeys := make(map[string]bool)

	for _, targetJasResults := range allTargetJasResults {
		if targetJasResults == nil {
			continue
		}

		for _, targetRun := range targetJasResults.GetVulnerabilitiesResults(jasutils.Secrets) {
			extractLocationsOnly(targetRun, targetKeys)
		}
		for _, targetRun := range targetJasResults.GetViolationsResults(jasutils.Secrets) {
			extractLocationsOnly(targetRun, targetKeys)
		}
		for _, targetRun := range targetJasResults.GetVulnerabilitiesResults(jasutils.IaC) {
			extractLocationsOnly(targetRun, targetKeys)
		}
		for _, targetRun := range targetJasResults.GetViolationsResults(jasutils.IaC) {
			extractLocationsOnly(targetRun, targetKeys)
		}
		for _, targetRun := range targetJasResults.GetVulnerabilitiesResults(jasutils.Sast) {
			extractFingerprints(targetRun, targetKeys)
		}
		for _, targetRun := range targetJasResults.GetViolationsResults(jasutils.Sast) {
			extractFingerprints(targetRun, targetKeys)
		}
	}

	log.Debug("[DIFF] Built target fingerprint set with", len(targetKeys), "unique keys")

	sourceSecrets := countSarifResults(sourceJasResults.JasVulnerabilities.SecretsScanResults) +
		countSarifResults(sourceJasResults.JasViolations.SecretsScanResults)
	sourceIac := countSarifResults(sourceJasResults.JasVulnerabilities.IacScanResults) +
		countSarifResults(sourceJasResults.JasViolations.IacScanResults)
	sourceSast := countSarifResults(sourceJasResults.JasVulnerabilities.SastScanResults) +
		countSarifResults(sourceJasResults.JasViolations.SastScanResults)

	log.Debug("[DIFF] Source findings before diff - Secrets:", sourceSecrets, "| IaC:", sourceIac, "| SAST:", sourceSast)

	filteredJasResults := &JasScansResults{}

	filteredJasResults.JasVulnerabilities.SecretsScanResults = filterSarifRuns(
		sourceJasResults.JasVulnerabilities.SecretsScanResults, targetKeys)
	filteredJasResults.JasVulnerabilities.IacScanResults = filterSarifRuns(
		sourceJasResults.JasVulnerabilities.IacScanResults, targetKeys)
	filteredJasResults.JasVulnerabilities.SastScanResults = filterSarifRuns(
		sourceJasResults.JasVulnerabilities.SastScanResults, targetKeys)

	filteredJasResults.JasViolations.SecretsScanResults = filterSarifRuns(
		sourceJasResults.JasViolations.SecretsScanResults, targetKeys)
	filteredJasResults.JasViolations.IacScanResults = filterSarifRuns(
		sourceJasResults.JasViolations.IacScanResults, targetKeys)
	filteredJasResults.JasViolations.SastScanResults = filterSarifRuns(
		sourceJasResults.JasViolations.SastScanResults, targetKeys)

	diffSecrets := countSarifResults(filteredJasResults.JasVulnerabilities.SecretsScanResults) +
		countSarifResults(filteredJasResults.JasViolations.SecretsScanResults)
	diffIac := countSarifResults(filteredJasResults.JasVulnerabilities.IacScanResults) +
		countSarifResults(filteredJasResults.JasViolations.IacScanResults)
	diffSast := countSarifResults(filteredJasResults.JasVulnerabilities.SastScanResults) +
		countSarifResults(filteredJasResults.JasViolations.SastScanResults)

	log.Info("[DIFF] New findings after diff - Secrets:", diffSecrets, "| IaC:", diffIac, "| SAST:", diffSast)
	log.Info("[DIFF] Filtered out - Secrets:", sourceSecrets-diffSecrets, "| IaC:", sourceIac-diffIac, "| SAST:", sourceSast-diffSast)

	return filteredJasResults
}

func countSarifResults(runs []*sarif.Run) int {
	count := 0
	for _, run := range runs {
		if run != nil {
			count += len(run.Results)
		}
	}
	return count
}

func extractFingerprints(run *sarif.Run, targetKeys map[string]bool) {
	for _, result := range run.Results {
		if result.Fingerprints != nil {
			key := getResultFingerprint(result)
			if key != "" {
				targetKeys[key] = true
			}
		} else {
			for _, location := range result.Locations {
				key := getRelativeLocationFileName(location, run.Invocations) + getLocationSnippetText(location)
				targetKeys[key] = true
			}
		}
	}
}

func extractLocationsOnly(run *sarif.Run, targetKeys map[string]bool) {
	for _, result := range run.Results {
		for _, location := range result.Locations {
			key := getRelativeLocationFileName(location, run.Invocations) + getLocationSnippetText(location)
			targetKeys[key] = true
		}
	}
}

func getResultFingerprint(result *sarif.Result) string {
	if result.Fingerprints != nil {
		if value, ok := result.Fingerprints["precise_sink_and_sink_function"]; ok {
			return value
		}
	}
	return ""
}

func getLocationSnippetText(location *sarif.Location) string {
	if location.PhysicalLocation != nil && location.PhysicalLocation.Region != nil &&
		location.PhysicalLocation.Region.Snippet != nil && location.PhysicalLocation.Region.Snippet.Text != nil {
		return *location.PhysicalLocation.Region.Snippet.Text
	}
	return ""
}

func getRelativeLocationFileName(location *sarif.Location, invocations []*sarif.Invocation) string {
	wd := ""
	if len(invocations) > 0 {
		wd = getInvocationWorkingDirectory(invocations[0])
	}
	filePath := getLocationFileName(location)
	if filePath != "" {
		return extractRelativePath(filePath, wd)
	}
	return ""
}

func getInvocationWorkingDirectory(invocation *sarif.Invocation) string {
	if invocation != nil && invocation.WorkingDirectory != nil && invocation.WorkingDirectory.URI != nil {
		return *invocation.WorkingDirectory.URI
	}
	return ""
}

func getLocationFileName(location *sarif.Location) string {
	if location != nil && location.PhysicalLocation != nil && location.PhysicalLocation.ArtifactLocation != nil && location.PhysicalLocation.ArtifactLocation.URI != nil {
		return *location.PhysicalLocation.ArtifactLocation.URI
	}
	return ""
}

func extractRelativePath(resultPath string, projectRoot string) string {
	resultPath = strings.TrimPrefix(resultPath, "file:///private")
	resultPath = strings.TrimPrefix(resultPath, "file:///")
	projectRoot = strings.TrimPrefix(projectRoot, "file:///private")
	projectRoot = strings.TrimPrefix(projectRoot, "file:///")
	projectRoot = strings.TrimPrefix(projectRoot, "/")

	relativePath := strings.ReplaceAll(resultPath, projectRoot, "")
	trimSlash := strings.TrimPrefix(relativePath, string(filepath.Separator))
	return strings.TrimPrefix(trimSlash, "/")
}

func filterSarifRuns(sourceRuns []*sarif.Run, targetKeys map[string]bool) []*sarif.Run {
	var filteredRuns []*sarif.Run

	for _, run := range sourceRuns {
		var filteredResults []*sarif.Result

		for _, result := range run.Results {
			if result.Fingerprints != nil {
				if !targetKeys[getResultFingerprint(result)] {
					filteredResults = append(filteredResults, result)
				}
			} else {
				var filteredLocations []*sarif.Location
				for _, location := range result.Locations {
					key := getRelativeLocationFileName(location, run.Invocations) + getLocationSnippetText(location)
					if !targetKeys[key] {
						filteredLocations = append(filteredLocations, location)
					}
				}

				if len(filteredLocations) > 0 {
					newResult := *result
					newResult.Locations = filteredLocations
					filteredResults = append(filteredResults, &newResult)
				}
			}
		}

		if len(filteredResults) > 0 {
			filteredRun := *run
			filteredRun.Results = filteredResults
			filteredRuns = append(filteredRuns, &filteredRun)
		}
	}

	return filteredRuns
}
