package audit

import (
	"github.com/jfrog/jfrog-cli-security/utils/gitutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-client-go/utils/log"
)

func filterResultsNotInDiff(scanResults *results.SecurityCommandResults, changes *gitutils.ChangesRelevantToScan) (onlyResultsInDiff *results.SecurityCommandResults) {
	if changes == nil || !changes.HasFileChanges() {
		log.Debug("No diff targets to filter results")
		return scanResults
	}
	diffDescriptors := getDescriptorsFromDiff(changes.GetChangedFilesPaths())
	// Create a new results object with the same metadata
	onlyResultsInDiff = results.NewCommandResults(scanResults.CmdType)
	onlyResultsInDiff.CommandMetaData = scanResults.CommandMetaData
	// Loop over the scan targets and filter out the results that are not in the diff
	for _, target := range scanResults.Targets {
		// Add scan target to the new results object with the same metadata and no results
		filterTarget := onlyResultsInDiff.NewScanResults(target.ScanTarget)
		filterTarget.Errors = target.Errors
		// Go over the results and filter out the ones that are not in the diff
		filterTarget.ScaResults = filterScaResultsNotInDiff(target.ScaResults, diffDescriptors)
		filterTarget.JasResults = filterJasResultsNotInDiff(target.JasResults, changes)
	}
	return
}

func getDescriptorsFromDiff(diffTargets []string) (descriptors []string) {
	return append(descriptors, diffTargets...)
}

// Filter SCA results that are not in the diff, if at least one SCA descriptor is in the diff, the target is in the diff
// TODO: when we can discover and match SCA issue to location at file level, we can improve filter capabilities
func filterScaResultsNotInDiff(scaResults *results.ScaScanResults, changedDescriptors []string) (filterResults *results.ScaScanResults) {
	if len(changedDescriptors) == 0 {
		log.Debug("No diff targets to filter SCA results")
		return scaResults
	}
	log.Warn("Filtering SCA results based on diff is not fully supported yet, all SCA results at the file level are included if changed")
	return scaResults
}

func filterJasResultsNotInDiff(jasResults *results.JasScansResults, changes *gitutils.ChangesRelevantToScan) (filterResults *results.JasScansResults) {
	return jasResults
}
