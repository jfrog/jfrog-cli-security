package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	// "github.com/jfrog/jfrog-cli-core/artifactory/commands/utils"
	"github.com/jfrog/jfrog-cli-security/commands/audit"
	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	clientutils "github.com/jfrog/jfrog-client-go/utils"
	"golang.org/x/exp/slices"

	// "golang.org/x/exp/slices"

	"github.com/jfrog/jfrog-client-go/utils/log"
)

const (
	initialCommitHash = "0000000000000000000000000000000000000000"
)

type GitAuditCommand struct {
	Source string
	Target string
	audit.AuditCommand
}

func NewGitAuditCommand(auditCmd *audit.AuditCommand) *GitAuditCommand {
	return &GitAuditCommand{AuditCommand: *auditCmd}
}

func (gaCmd *GitAuditCommand) SetSource(source string) *GitAuditCommand {
	gaCmd.Source = source
	return gaCmd
}

func (gaCmd *GitAuditCommand) SetTarget(target string) *GitAuditCommand {
	gaCmd.Target = target
	return gaCmd
}

func (gaCmd *GitAuditCommand) Run() (err error) {
	log.Info(fmt.Sprintf("Calculating diff between source commit `%s` and target commit `%s`", gaCmd.Source, gaCmd.Target))
	wd, err := os.Getwd()
	if err != nil {
		return
	}
	gitManager := clientutils.NewGitManager(wd)
	// Calculate diff
	filesChanged, err := GetFileDiff(gitManager, gaCmd.Source, gaCmd.Target)
	if err != nil {
		return
	}
	if len(filesChanged) == 0 {
		log.Info("No files changed between the commits")
		return
	} else {
		log.Debug(fmt.Sprintf("Files changed: %v", filesChanged))
	}
	// Get required scans by file changes
	if requiredScans := getRequiredScans(gaCmd.ScansToPerform(), filesChanged); len(requiredScans) > 0 {
		log.Info(fmt.Sprintf("Preforming the following scans: %v", requiredScans))
		gaCmd.AuditParams.SetScansToPerform(requiredScans)
	} else {
		log.Info("No scans required for the changed files")
		return
	}
	// Change to target commit (TODO: at the end, return to the original commit or branch to avoid side effects)
	if gitManager.GetRevision() != gaCmd.Target {
		log.Info(fmt.Sprintf("Checking out to target commit `%s`", gaCmd.Target))
		if err = checkoutToCommit(gitManager, gaCmd.Target); err != nil {
			return
		}
	}
	// Run audit
	results, err := gaCmd.RunAuditCommand(false)
	if err != nil {
		return
	}
	// Filter results by added lines
	finalResults := filterResultsByFiles(results, filesChanged)
	// Print results
	if err = gaCmd.PrintAuditResults(finalResults); err != nil {
		return
	}
	err = gaCmd.GetResultsError(finalResults)
	return
}

func checkoutToCommit(gitManager *clientutils.GitManager, commitHash string) (err error) {
	stdOut, stdErr, err := gitManager.ExecGit("checkout", commitHash)
	if stdErr != "" {
		// log.Warn(fmt.Sprintf("Git checkout stderr:\n%s", stdErr))
	}
	if err != nil {
		return
	}
	if stdOut != "" {
		// log.Debug(fmt.Sprintf("Git checkout stdout:\n%s", stdOut))
	}
	return
}

func getRequiredScans(requestedScans []utils.SubScanType, filesChanged []string) []utils.SubScanType {
	// TODO: what if already provided?
	requiredScans := []utils.SubScanType{}
	tech := shouldRunScaScan(requestedScans, filesChanged)
	shouldRunJas := shouldRunJasScan(filesChanged, tech)
	// Calculate required scans
	if tech != nil {
		log.Debug(fmt.Sprintf("Technology `%s` is detected in the changed files", tech.ToFormal()))
		requiredScans = append(requiredScans, utils.ScaScan)
		if len(requestedScans) == 0 || slices.Contains(requestedScans, utils.ContextualAnalysisScan) {
			requiredScans = append(requiredScans, utils.ContextualAnalysisScan)
		}
	}
	if shouldRunJas {
		requiredScans = append(requiredScans, utils.IacScan, utils.SastScan, utils.SecretsScan)
	} else {
		log.Debug("Files changed are only related to technology or not changed at all. Skipping IaC, SAST and Secrets scans...")
	}
	return requiredScans
}

// Check if the files changed are related to the technology
func shouldRunScaScan(requestedScans []utils.SubScanType, filesChanged []string) *techutils.Technology {
	if len(requestedScans) > 0 && !slices.Contains(requestedScans, utils.ScaScan){
		log.Debug("SCA scan is not requested. Skipping...")
		return nil
	}
	for _, file := range filesChanged {
		for _, tech := range techutils.GetAllTechnologiesList() {
			isIndicator, err := tech.IsIndicator(file)
			if err != nil {
				log.Warn(fmt.Sprintf("Failed to check if file `%s` is an indicator for technology `%s`: %s", file, tech.ToFormal(), err.Error()))
				continue
			}
			if tech.IsDescriptor(file) || isIndicator {
				log.Debug(fmt.Sprintf("File `%s` is an indicator for technology `%s`", file, tech.ToFormal()))
				return &tech
			}
		}
	}
	return nil
}

// Check if the files changed are not related to the technology
func shouldRunJasScan(filesChanged []string, tech *techutils.Technology) bool {
	if len(filesChanged) == 0 {
		return false
	}
	if tech == nil {
		return true
	}
	for _, file := range filesChanged {
		isIndicator, err := tech.IsIndicator(file)
		if err != nil {
			log.Warn(fmt.Sprintf("Failed to check if file `%s` is an indicator for technology `%s`: %s", file, tech.ToFormal(), err.Error()))
			continue
		}
		if !tech.IsDescriptor(file) && !isIndicator {
			log.Debug(fmt.Sprintf("File `%s` is not an indicator for technology `%s`", file, tech.ToFormal()))
			return true
		}
	}
	return false
}

func shouldRunScan(requiredScans []utils.SubScanType, requestedScanType utils.SubScanType) bool {
	if len(requiredScans) == 0 {
		return true
	}
	return slices.Contains(requiredScans, requestedScanType)
}

func getAsFullPath(wd string, files ...string) ([]string) {
	fullPaths := []string{}
	for _, file := range files {
		fullPaths = append(fullPaths, filepath.Join(wd,file))
	}
	return fullPaths
}

func filterResultsByFiles(results *utils.Results, changedFiles []string) *utils.Results {
	// filteredResults := utils.NewAuditResults()
	// Filter SCA results
	// for _, scaResult := range results.ScaResults {
	// 	// for _, xrayResults := range scaResult.XrayResults {
	// 	// 	// if slices.Contains(changedFiles, xrayResults.FileName) {
	// 	// 	// 	filteredResults.ScaResults = append(filteredResults.ScaResults, scaResult)
	// 	// 	// 	break
	// 	// 	// }
	// 	// }
	// }
	return results
}


// move to GitManager in client-go

// GetFileDiff returns the list of files changed between two commits.
// Source - can be a branch or a commit hash
// TODO: Target - can be a branch or a commit hash? (not sure) - need to check
func GetFileDiff(gitManager *clientutils.GitManager, source string, target string) (filesChanged []string, err error) {
	stdout, stderr, err := gitManager.ExecGit("diff", "--name-only", source, target)
	if stderr != "" {
		log.Warn(fmt.Sprintf("Git diff stderr:\n%s", stderr))
	}
	if err != nil {
		return
	}
	// Split the output into lines and return as a slice of strings
	changedFiles := strings.Split(strings.TrimSpace(stdout), "\n")
	return changedFiles, nil
}