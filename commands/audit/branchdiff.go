package audit

import (
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-client-go/utils/log"
)

// BranchDiffParams holds parameters for branch diff scanning
type BranchDiffParams struct {
	// Base audit params (used for both target and source)
	BaseParams *AuditParams
	// Target branch working directory (the branch being merged into, e.g., main)
	TargetWorkingDir string
	// Source branch working directory (the branch with changes, e.g., feature branch)
	SourceWorkingDir string
}

// NewBranchDiffParams creates new branch diff parameters
func NewBranchDiffParams() *BranchDiffParams {
	return &BranchDiffParams{
		BaseParams: NewAuditParams(),
	}
}

func (p *BranchDiffParams) SetBaseParams(params *AuditParams) *BranchDiffParams {
	p.BaseParams = params
	return p
}

func (p *BranchDiffParams) SetTargetWorkingDir(dir string) *BranchDiffParams {
	p.TargetWorkingDir = dir
	return p
}

func (p *BranchDiffParams) SetSourceWorkingDir(dir string) *BranchDiffParams {
	p.SourceWorkingDir = dir
	return p
}

// RunBranchDiffAudit runs a diff scan between target and source branches.
// It scans target first, then source, computes the diff, and returns only NEW findings.
// Logs are sequential: all target logs first, then all source logs.
//
// Returns:
//   - Unified diffed results containing only new vulnerabilities in source
//   - Status codes are merged (worst of target + source) for partial results filtering
func RunBranchDiffAudit(params *BranchDiffParams) (diffResults *results.SecurityCommandResults) {
	log.Info("========== BRANCH DIFF SCAN ==========")
	log.Info("Target branch:", params.TargetWorkingDir)
	log.Info("Source branch:", params.SourceWorkingDir)
	log.Info("=======================================")

	// Phase 1: Scan TARGET branch
	log.Info("")
	log.Info("========== SCANNING TARGET BRANCH ==========")
	targetParams := cloneAuditParams(params.BaseParams)
	targetParams.SetWorkingDirs([]string{params.TargetWorkingDir})
	targetParams.SetDiffMode(true)
	targetParams.SetResultsToCompare(nil)   // No comparison for target - we're collecting baseline
	targetParams.SetUploadCdxResults(false) // Don't upload intermediate results

	targetResults := RunAudit(targetParams)

	if targetResults.GeneralError != nil {
		log.Error("Target branch scan failed:", targetResults.GeneralError)
		return targetResults
	}
	log.Info("========== TARGET BRANCH SCAN COMPLETE ==========")
	log.Info("")

	// Phase 2: Scan SOURCE branch
	log.Info("========== SCANNING SOURCE BRANCH ==========")
	sourceParams := cloneAuditParams(params.BaseParams)
	sourceParams.SetWorkingDirs([]string{params.SourceWorkingDir})
	sourceParams.SetDiffMode(true)
	sourceParams.SetResultsToCompare(targetResults) // SCA will use this for internal diff
	sourceParams.SetUploadCdxResults(false)         // Don't upload intermediate results

	sourceResults := RunAudit(sourceParams)

	if sourceResults.GeneralError != nil {
		log.Error("Source branch scan failed:", sourceResults.GeneralError)
		return sourceResults
	}
	log.Info("========== SOURCE BRANCH SCAN COMPLETE ==========")
	log.Info("")

	// Phase 3: Compute JAS diff (SCA diff is already done internally)
	log.Info("========== COMPUTING DIFF ==========")
	jasDiffResults := results.CompareJasResults(targetResults, sourceResults)

	// Phase 4: Unify SCA (already diffed) + JAS (just diffed) results
	diffResults = results.UnifyScaAndJasResults(sourceResults, jasDiffResults)

	// Phase 5: Merge status codes from both target and source
	// This ensures partial results filtering works correctly - if ANY scan failed
	// on either branch, the corresponding scanner results should be filtered
	targetStatus := targetResults.GetStatusCodes()
	sourceStatus := sourceResults.GetStatusCodes()
	mergedStatus := results.MergeStatusCodes(targetStatus, sourceStatus)

	// Apply merged status to all targets in diff results
	for _, target := range diffResults.Targets {
		target.ResultsStatus = mergedStatus
	}

	// Copy violation status code if set
	if targetResults.ViolationsStatusCode != nil || sourceResults.ViolationsStatusCode != nil {
		mergedViolationStatus := mergeViolationStatus(targetResults.ViolationsStatusCode, sourceResults.ViolationsStatusCode)
		diffResults.ViolationsStatusCode = mergedViolationStatus
	}

	log.Info("========== DIFF COMPLETE ==========")
	log.Info("Diff results: ", len(diffResults.Targets), " targets with new findings")

	return diffResults
}

// cloneAuditParams creates a shallow copy of AuditParams for independent configuration
func cloneAuditParams(params *AuditParams) *AuditParams {
	cloned := NewAuditParams()

	// Copy basic params
	cloned.AuditBasicParams = params.AuditBasicParams

	// Copy all other fields
	cloned.SetResultsContext(params.resultsContext)
	cloned.SetGitContext(params.gitContext)
	cloned.SetBomGenerator(params.bomGenerator)
	cloned.SetCustomBomGenBinaryPath(params.customBomGenBinaryPath)
	cloned.SetCustomAnalyzerManagerBinaryPath(params.customAnalyzerManagerBinaryPath)
	cloned.SetSastRules(params.sastRules)
	cloned.SetScaScanStrategy(params.scaScanStrategy)
	cloned.SetStartTime(params.startTime)
	cloned.SetMultiScanId(params.multiScanId)
	cloned.SetMinSeverityFilter(params.minSeverityFilter)
	cloned.SetFixableOnly(params.fixableOnly)
	cloned.SetThirdPartyApplicabilityScan(params.thirdPartyApplicabilityScan)
	cloned.SetThreads(params.threads)
	cloned.SetScansResultsOutputDir(params.scanResultsOutputDir)
	cloned.SetViolationGenerator(params.violationGenerator)
	cloned.SetAllowedLicenses(params.allowedLicenses)
	cloned.SetRtResultRepository(params.rtResultRepository)

	return cloned
}

// mergeViolationStatus returns the worst (non-zero) violation status
func mergeViolationStatus(a, b *int) *int {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	if *a != 0 {
		return a
	}
	return b
}
