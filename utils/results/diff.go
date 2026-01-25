package results

import (
	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"
)

// MergeScaAndJasResults merges SCA results with JAS diff results into a single SecurityCommandResults.
// SCA results provide the base (including ScaResults and GitContext), JAS results provide the JAS findings.
func MergeScaAndJasResults(scaResults, jasDiffResults *SecurityCommandResults) *SecurityCommandResults {
	unifiedResults := &SecurityCommandResults{
		ResultsMetaData: jasDiffResults.ResultsMetaData,
	}
	// Prefer SCA's GitContext (contains PR upload path info)
	if scaResults.GitContext != nil {
		unifiedResults.GitContext = scaResults.GitContext
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
			ResultsStatus:    scaTarget.ResultsStatus, // Preserve SCA scan status
		}

		// Merge JAS status codes if JAS scans were performed
		// Note: ContextualAnalysis is part of SCA, not JAS, so we don't override it here
		if jasTarget != nil {
			// JAS status codes take precedence (they include the JAS scan results)
			if jasTarget.ResultsStatus.SastScanStatusCode != nil {
				unifiedTarget.ResultsStatus.SastScanStatusCode = jasTarget.ResultsStatus.SastScanStatusCode
			}
			if jasTarget.ResultsStatus.IacScanStatusCode != nil {
				unifiedTarget.ResultsStatus.IacScanStatusCode = jasTarget.ResultsStatus.IacScanStatusCode
			}
			if jasTarget.ResultsStatus.SecretsScanStatusCode != nil {
				unifiedTarget.ResultsStatus.SecretsScanStatusCode = jasTarget.ResultsStatus.SecretsScanStatusCode
			}
			if jasTarget.ResultsStatus.MaliciousScanStatusCode != nil {
				unifiedTarget.ResultsStatus.MaliciousScanStatusCode = jasTarget.ResultsStatus.MaliciousScanStatusCode
			}
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

// FilterNewJasFindings filters source JAS results to exclude findings that exist in target.
// Returns only NEW findings in source that don't exist in target.
func FilterNewJasFindings(targetResults, sourceResults *SecurityCommandResults) *SecurityCommandResults {
	log.Info("[DIFF] Starting JAS diff calculation")
	log.Debug("[DIFF] Comparing", len(sourceResults.Targets), "source targets against", len(targetResults.Targets), "target targets")

	diffResults := &SecurityCommandResults{
		ResultsMetaData: sourceResults.ResultsMetaData,
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

		diffJasResults := excludeExistingFindingsInTargets(sourceTarget.JasResults, allTargetJasResults...)

		diffTarget := &TargetResults{
			ScanTarget:    sourceTarget.ScanTarget,
			JasResults:    diffJasResults,
			ResultsStatus: sourceTarget.ResultsStatus, // Preserve JAS scan status codes
		}

		diffResults.Targets = append(diffResults.Targets, diffTarget)
	}

	return diffResults
}

// excludeExistingFindingsInTargets removes findings from source that already exist in any of the target results.
// Returns a new JasScansResults containing only findings that are NEW in source (not present in targets).
func excludeExistingFindingsInTargets(sourceJasResults *JasScansResults, targetJasResultsToExclude ...*JasScansResults) *JasScansResults {
	if sourceJasResults == nil {
		return nil
	}

	if len(targetJasResultsToExclude) == 0 {
		return sourceJasResults
	}

	targetKeys := extractAllJasResultKeys(targetJasResultsToExclude...)

	sourceSecrets, sourceIac, sourceSast := countJasFindings(sourceJasResults)

	log.Debug("[DIFF] Source findings before diff - Secrets:", sourceSecrets, "| IaC:", sourceIac, "| SAST:", sourceSast)

	filteredJasResults := &JasScansResults{}

	filteredJasResults.JasVulnerabilities.SecretsScanResults = filterNewSarifFindings(
		sourceJasResults.JasVulnerabilities.SecretsScanResults, targetKeys)
	filteredJasResults.JasVulnerabilities.IacScanResults = filterNewSarifFindings(
		sourceJasResults.JasVulnerabilities.IacScanResults, targetKeys)
	filteredJasResults.JasVulnerabilities.SastScanResults = filterNewSarifFindings(
		sourceJasResults.JasVulnerabilities.SastScanResults, targetKeys)

	filteredJasResults.JasViolations.SecretsScanResults = filterNewSarifFindings(
		sourceJasResults.JasViolations.SecretsScanResults, targetKeys)
	filteredJasResults.JasViolations.IacScanResults = filterNewSarifFindings(
		sourceJasResults.JasViolations.IacScanResults, targetKeys)
	filteredJasResults.JasViolations.SastScanResults = filterNewSarifFindings(
		sourceJasResults.JasViolations.SastScanResults, targetKeys)

	diffSecrets, diffIac, diffSast := countJasFindings(filteredJasResults)

	log.Info("[DIFF] New findings after diff - Secrets:", diffSecrets, "| IaC:", diffIac, "| SAST:", diffSast)
	log.Info("[DIFF] Filtered out - Secrets:", sourceSecrets-diffSecrets, "| IaC:", sourceIac-diffIac, "| SAST:", sourceSast-diffSast)

	return filteredJasResults
}

// countJasFindings returns the count of (secrets, iac, sast) findings in the JAS results.
func countJasFindings(jasResults *JasScansResults) (secrets, iac, sast int) {
	if jasResults == nil {
		return
	}
	secrets = countSarifResults(jasResults.JasVulnerabilities.SecretsScanResults) +
		countSarifResults(jasResults.JasViolations.SecretsScanResults)
	iac = countSarifResults(jasResults.JasVulnerabilities.IacScanResults) +
		countSarifResults(jasResults.JasViolations.IacScanResults)
	sast = countSarifResults(jasResults.JasVulnerabilities.SastScanResults) +
		countSarifResults(jasResults.JasViolations.SastScanResults)
	return
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

// extractAllJasResultKeys extracts unique identifiers from all JAS results for diff comparison.
// For Secrets/IaC: uses file path + snippet as key (location-based matching).
// For SAST: uses fingerprint when available, falls back to location-based matching.
func extractAllJasResultKeys(jasResults ...*JasScansResults) map[string]bool {
	targetKeys := make(map[string]bool)
	for _, jasResult := range jasResults {
		if jasResult == nil {
			continue
		}
		// Secrets and IaC use location-based matching
		extractLocationsOnly(targetKeys,
			jasResult.GetVulnerabilitiesResults(jasutils.Secrets)...)
		extractLocationsOnly(targetKeys,
			jasResult.GetViolationsResults(jasutils.Secrets)...)
		extractLocationsOnly(targetKeys,
			jasResult.GetVulnerabilitiesResults(jasutils.IaC)...)
		extractLocationsOnly(targetKeys,
			jasResult.GetViolationsResults(jasutils.IaC)...)
		// SAST uses fingerprint-based matching when available
		extractFingerprints(targetKeys,
			jasResult.GetVulnerabilitiesResults(jasutils.Sast)...)
		extractFingerprints(targetKeys,
			jasResult.GetViolationsResults(jasutils.Sast)...)
	}
	return targetKeys
}

// extractFingerprints extracts SAST fingerprints (or falls back to locations) for diff matching.
func extractFingerprints(targetKeys map[string]bool, runs ...*sarif.Run) {
	for _, run := range runs {
		for _, result := range run.Results {
			if sarifutils.IsFingerprintsExists(result) {
				key := sarifutils.GetSastDiffFingerprint(result)
				if key != "" {
					targetKeys[key] = true
				}
			} else {
				for _, location := range result.Locations {
					key := sarifutils.GetRelativeLocationFileName(location, run.Invocations) + sarifutils.GetLocationSnippetText(location)
					targetKeys[key] = true
				}
			}
		}
	}
}

// extractLocationsOnly extracts location-based keys (file path + snippet) for diff matching.
func extractLocationsOnly(targetKeys map[string]bool, runs ...*sarif.Run) {
	for _, run := range runs {
		for _, result := range run.Results {
			for _, location := range result.Locations {
				key := sarifutils.GetRelativeLocationFileName(location, run.Invocations) + sarifutils.GetLocationSnippetText(location)
				targetKeys[key] = true
			}
		}
	}
}

// filterNewSarifFindings removes findings from sourceRuns that already exist in targetKeys.
// For SAST results with fingerprints, matches by fingerprint.
// For Secrets/IaC results, matches by file location + snippet text.
func filterNewSarifFindings(sourceRuns []*sarif.Run, targetKeys map[string]bool) []*sarif.Run {
	var filteredRuns []*sarif.Run

	for _, run := range sourceRuns {
		var filteredResults []*sarif.Result

		for _, result := range run.Results {
			if sarifutils.IsFingerprintsExists(result) {
				if !targetKeys[sarifutils.GetSastDiffFingerprint(result)] {
					filteredResults = append(filteredResults, result)
				}
			} else {
				var filteredLocations []*sarif.Location
				for _, location := range result.Locations {
					key := sarifutils.GetRelativeLocationFileName(location, run.Invocations) + sarifutils.GetLocationSnippetText(location)
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
