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
	log.Info(fmt.Sprintf("Files changed: %v", filesChanged))
	// Get required scans
	requiredScans := getRequiredScans(filesChanged)
	if len(requiredScans) > 0 {
		log.Info(fmt.Sprintf("Preforming the following scans: %v", requiredScans))
		gaCmd.AuditParams.SetScansToPerform(requiredScans)
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

func getRequiredScans(filesChanged []string) []utils.SubScanType {
	requiredScans := []utils.SubScanType{}
	shouldAddJas := false
	for _, tech := range techutils.GetAllTechnologiesList() {
		// Check if the files changed are related to the technology
		// If yes, add SCA to the required scans
		for _, file := range filesChanged {
			isIndicator, err := tech.IsIndicator(file)
			if err != nil {
				log.Warn(fmt.Sprintf("Failed to check if file `%s` is an indicator for technology `%s`", file, tech.ToFormal()))
				continue
			}
			if tech.IsDescriptor(file) || isIndicator {
				
			} else {
				// Other, not technology related files, are changed. Add JAS to the required scans
				shouldAddJas = true
			}
		}
	}
	if shouldAddJas {
		if slices.Contains(requiredScans, utils.ScaScan) {
			requiredScans = append(requiredScans, utils.ContextualAnalysisScan)
		}
		requiredScans = append(requiredScans, utils.IacScan, utils.SastScan, utils.SecretsScan)
	}
	return requiredScans
}

func getAsFullPath(files []string) ([]string, error) {
	fullPaths := []string{}
	wd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	for _, file := range files {
		fullPaths = append(fullPaths, filepath.Join(wd,file))
	}
	return fullPaths, nil
}

func filterResultsByFiles(results *utils.Results, changedFiles []string) *utils.Results {
	filteredResults := utils.NewAuditResults()
	// Filter SCA results
	for _, scaResult := range results.ScaResults {

		for _, xrayResults := range scaResult.XrayResults {

		}
	}
	return filteredResults
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