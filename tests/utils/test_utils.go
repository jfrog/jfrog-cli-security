package utils

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jfrog/jfrog-cli-security/sca/bom/indexer"
	"github.com/jfrog/jfrog-cli-security/sca/bom/xrayplugin/plugin"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"

	biutils "github.com/jfrog/build-info-go/utils"
	"github.com/jfrog/jfrog-cli-security/jas"

	"github.com/jfrog/jfrog-cli-core/v2/utils/xray"
	xrayUtils "github.com/jfrog/jfrog-cli-security/utils/xray"
	clientUtils "github.com/jfrog/jfrog-client-go/utils"
	xrayApi "github.com/jfrog/jfrog-client-go/xray/services/utils"
	"github.com/stretchr/testify/require"

	"github.com/jfrog/gofrog/version"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	configTests "github.com/jfrog/jfrog-cli-security/tests"
	"github.com/stretchr/testify/assert"

	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	clientTests "github.com/jfrog/jfrog-client-go/utils/tests"
)

// SkipTestIfDurationNotPassed skips the test if the specified duration in days hasn't passed since the given date.
// dateStr should be in the format "02-01-2006" (DD-MM-YYYY).
// durationDays is the number of days that should have passed.
func SkipTestIfDurationNotPassed(t *testing.T, dateStr string, durationDays int, msg string) {
	givenDate, err := time.Parse("02-01-2006", dateStr)
	if err != nil {
		t.Fatalf("Invalid date format '%s'. Expected format: DD-MM-YYYY", dateStr)
	}

	daysSinceDate := int(time.Since(givenDate).Hours() / 24)
	if daysSinceDate < durationDays {
		if msg == "" {
			t.Skipf("Skipping test. Only %d days have passed since %s, but %d days are required.", daysSinceDate, dateStr, durationDays)
		} else {
			t.Skipf("Skipping test (%d/%d days have passed since %s, but %d days are required.) Reason: %s", daysSinceDate, durationDays, dateStr, durationDays, msg)
		}
	} else if daysSinceDate > durationDays {
		t.Log("Continuing test. Required duration has passed. remove or update the SkipTestIfDurationNotPassed call.")
	}
}

func UnmarshalJson(t *testing.T, output string) formats.EnrichJson {
	var jsonMap formats.EnrichJson
	err := json.Unmarshal([]byte(output), &jsonMap)
	assert.NoError(t, err)
	return jsonMap
}

func UnmarshalXML(t *testing.T, output string) formats.Bom {
	var xmlMap formats.Bom
	err := xml.Unmarshal([]byte(output), &xmlMap)
	assert.NoError(t, err)
	return xmlMap
}

func GetAndValidateXrayVersion(t *testing.T, minVersion string) {
	xrayVersion, err := GetTestsXrayVersion()
	if err != nil {
		assert.NoError(t, err)
		return
	}
	ValidateXrayVersion(t, xrayVersion.GetVersion(), minVersion)
}

func ValidateXrayVersion(t *testing.T, xrayVersion, minVersion string) {
	if err := clientUtils.ValidateMinimumVersion(clientUtils.Xray, xrayVersion, minVersion); err != nil {
		t.Skip(err)
	}
}

func ValidateXscVersion(t *testing.T, xscVersion, minVersion string) {
	if err := clientUtils.ValidateMinimumVersion(clientUtils.Xsc, xscVersion, minVersion); err != nil {
		t.Skip(err)
	}
}

func GetTestsXrayVersion() (version.Version, error) {
	xrayVersion, err := configTests.XrAuth.GetVersion()
	return *version.NewVersion(xrayVersion), err
}

func ChangeWD(t *testing.T, newPath string) string {
	prevDir, err := os.Getwd()
	assert.NoError(t, err, "Failed to get current dir")
	clientTests.ChangeDirAndAssert(t, newPath)
	return prevDir
}

func convertSarifRunPathsForOS(runs ...*sarif.Run) {
	for r := range runs {
		for i := range runs[r].Invocations {
			if runs[r].Invocations[i].WorkingDirectory != nil && runs[r].Invocations[i].WorkingDirectory.URI != nil {
				*runs[r].Invocations[i].WorkingDirectory.URI = filepath.FromSlash(sarifutils.GetInvocationWorkingDirectory(runs[r].Invocations[i]))
			}
		}
		for i := range runs[r].Results {
			for j := range runs[r].Results[i].Locations {
				if runs[r].Results[i].Locations[j] != nil && runs[r].Results[i].Locations[j].PhysicalLocation != nil && runs[r].Results[i].Locations[j].PhysicalLocation.ArtifactLocation != nil && runs[r].Results[i].Locations[j].PhysicalLocation.ArtifactLocation.URI != nil {
					*runs[r].Results[i].Locations[j].PhysicalLocation.ArtifactLocation.URI = getJasConvertedPath(sarifutils.GetLocationFileName(runs[r].Results[i].Locations[j]))
				}
			}
			for j := range runs[r].Results[i].CodeFlows {
				for k := range runs[r].Results[i].CodeFlows[j].ThreadFlows {
					for l := range runs[r].Results[i].CodeFlows[j].ThreadFlows[k].Locations {
						if runs[r].Results[i].CodeFlows[j].ThreadFlows[k].Locations[l] != nil && runs[r].Results[i].CodeFlows[j].ThreadFlows[k].Locations[l].Location != nil && runs[r].Results[i].CodeFlows[j].ThreadFlows[k].Locations[l].Location.PhysicalLocation != nil && runs[r].Results[i].CodeFlows[j].ThreadFlows[k].Locations[l].Location.PhysicalLocation.ArtifactLocation != nil && runs[r].Results[i].CodeFlows[j].ThreadFlows[k].Locations[l].Location.PhysicalLocation.ArtifactLocation.URI != nil {
							*runs[r].Results[i].CodeFlows[j].ThreadFlows[k].Locations[l].Location.PhysicalLocation.ArtifactLocation.URI = getJasConvertedPath(sarifutils.GetLocationFileName(runs[r].Results[i].CodeFlows[j].ThreadFlows[k].Locations[l].Location))
						}
					}
				}
			}
		}
	}
}

func ReadSimpleJsonResults(t *testing.T, path string) formats.SimpleJsonResults {
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	var results formats.SimpleJsonResults
	require.NoError(t, json.Unmarshal(content, &results))
	// replace paths separators
	for _, vulnerability := range results.Vulnerabilities {
		convertScaSimpleJsonPathsForOS(&vulnerability.Components, &vulnerability.ImpactPaths, &vulnerability.ImpactedDependencyDetails, &vulnerability.Cves)
	}
	for _, violation := range results.SecurityViolations {
		convertScaSimpleJsonPathsForOS(&violation.Components, &violation.ImpactPaths, &violation.ImpactedDependencyDetails, &violation.Cves)
	}
	for _, licenseViolation := range results.LicensesViolations {
		convertScaSimpleJsonPathsForOS(&licenseViolation.Components, &licenseViolation.ImpactPaths, &licenseViolation.ImpactedDependencyDetails, nil)
	}
	for _, orViolation := range results.OperationalRiskViolations {
		convertScaSimpleJsonPathsForOS(&orViolation.Components, nil, &orViolation.ImpactedDependencyDetails, nil)
	}
	for _, secret := range results.SecretsVulnerabilities {
		convertJasSimpleJsonPathsForOS(&secret)
	}
	for _, sast := range results.SastVulnerabilities {
		convertJasSimpleJsonPathsForOS(&sast)
	}
	for _, iac := range results.IacsVulnerabilities {
		convertJasSimpleJsonPathsForOS(&iac)
	}
	for _, secret := range results.SecretsViolations {
		convertJasSimpleJsonPathsForOS(&secret)
	}
	for _, sast := range results.SastViolations {
		convertJasSimpleJsonPathsForOS(&sast)
	}
	for _, iac := range results.IacsViolations {
		convertJasSimpleJsonPathsForOS(&iac)
	}
	return results
}

func convertJasSimpleJsonPathsForOS(jas *formats.SourceCodeRow) {
	if jas == nil {
		return
	}
	jas.File = getJasConvertedPath(jas.File)
	if jas.Applicability != nil {
		for i := range jas.Applicability.Evidence {
			jas.Applicability.Evidence[i].File = getJasConvertedPath(jas.Applicability.Evidence[i].File)
		}
	}
	for i := range jas.CodeFlow {
		for j := range jas.CodeFlow[i] {
			jas.CodeFlow[i][j].File = getJasConvertedPath(jas.CodeFlow[i][j].File)
		}
	}
}

func convertScaSimpleJsonPathsForOS(potentialComponents *[]formats.ComponentRow, potentialImpactPaths *[][]formats.ComponentRow, potentialImpactedDependencyDetails *formats.ImpactedDependencyDetails, potentialCves *[]formats.CveRow) {
	if potentialComponents != nil {
		components := *potentialComponents
		for i := range components {
			if components[i].Location != nil {
				components[i].Location.File = filepath.FromSlash(components[i].Location.File)
			}
		}
	}
	if potentialImpactPaths != nil {
		impactPaths := *potentialImpactPaths
		for i := range impactPaths {
			for j := range impactPaths[i] {
				if impactPaths[i][j].Location != nil {
					impactPaths[i][j].Location.File = filepath.FromSlash(impactPaths[i][j].Location.File)
				}
			}
		}
	}
	if potentialImpactedDependencyDetails != nil {
		impactedDependencyDetails := *potentialImpactedDependencyDetails
		for i := range impactedDependencyDetails.Components {
			if impactedDependencyDetails.Components[i].Location != nil {
				impactedDependencyDetails.Components[i].Location.File = filepath.FromSlash(impactedDependencyDetails.Components[i].Location.File)
			}
		}
	}
	if potentialCves != nil {
		cves := *potentialCves
		for i := range cves {
			if cves[i].Applicability != nil {
				for j := range cves[i].Applicability.Evidence {
					cves[i].Applicability.Evidence[j].File = filepath.ToSlash(cves[i].Applicability.Evidence[j].File)
				}
			}
		}
	}
}

func ReadSarifResults(t *testing.T, path string) *sarif.Report {
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	var results *sarif.Report
	require.NoError(t, json.Unmarshal(content, &results))
	// replace paths separators
	convertSarifRunPathsForOS(results.Runs...)
	return results
}

func ReadSummaryResults(t *testing.T, path string) formats.ResultsSummary {
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	var results formats.ResultsSummary
	require.NoError(t, json.Unmarshal(content, &results))
	// replace paths separators
	for _, targetResults := range results.Scans {
		targetResults.Target = filepath.FromSlash(targetResults.Target)
	}
	return results
}

func getJasConvertedPath(pathToConvert string) string {
	return filepath.FromSlash(strings.TrimPrefix(pathToConvert, "file://"))
}

func ChangeWDWithCallback(t *testing.T, newPath string) func() {
	prevDir := ChangeWD(t, newPath)
	return func() {
		clientTests.ChangeDirAndAssert(t, prevDir)
	}
}

func CreateTestIgnoreRules(t *testing.T, description string, filters xrayApi.IgnoreFilters) func() {
	xrayManager, err := xray.CreateXrayServiceManager(configTests.XrDetails)
	require.NoError(t, err)
	ignoreRuleId, err := xrayManager.CreateIgnoreRule(xrayApi.IgnoreRuleParams{
		// expired in one day
		Notes:         description,
		ExpiresAt:     time.Now().AddDate(0, 0, 1),
		IgnoreFilters: filters,
	})
	assert.NoError(t, err)
	return func() {
		assert.NoError(t, xrayManager.DeleteIgnoreRule(ignoreRuleId))
	}
}

func CreateSecurityPolicy(t *testing.T, policyName string, rules ...xrayApi.PolicyRule) (string, func()) {
	xrayManager, err := xray.CreateXrayServiceManager(configTests.XrDetails)
	require.NoError(t, err)
	// Create new default security policy.
	policyParams := xrayApi.PolicyParams{
		Name:  fmt.Sprintf("%s-%s-%s", policyName, *configTests.CiRunId, strconv.FormatInt(time.Now().Unix(), 10)),
		Type:  xrayApi.Security,
		Rules: rules,
	}
	if !assert.NoError(t, xrayManager.CreatePolicy(policyParams)) {
		return "", func() {}
	}
	return policyParams.Name, func() {
		assert.NoError(t, xrayManager.DeletePolicy(policyParams.Name))
	}
}

func CreateTestSecurityPolicy(t *testing.T, policyName string, severity xrayApi.Severity, failBuild bool, skipNotApplicable bool) (string, func()) {
	return CreateSecurityPolicy(t, policyName,
		xrayApi.PolicyRule{
			Name:     "sca_rule",
			Criteria: *xrayApi.CreateSeverityPolicyCriteria(severity, skipNotApplicable),
			Actions:  getBuildFailAction(failBuild),
			Priority: 1,
		},
		xrayApi.PolicyRule{
			Name:     "exposers_rule",
			Criteria: *xrayApi.CreateExposuresPolicyCriteria(severity, true, true, true, true),
			Actions:  getBuildFailAction(failBuild),
			Priority: 2,
		},
		xrayApi.PolicyRule{
			Name:     "sast_rule",
			Criteria: *xrayApi.CreateSastPolicyCriteria(severity),
			Actions:  getBuildFailAction(failBuild),
			Priority: 3,
		},
	)
}

func getBuildFailAction(failBuild bool) *xrayApi.PolicyAction {
	if failBuild {
		return &xrayApi.PolicyAction{
			FailBuild: clientUtils.Pointer(true),
		}
	}
	return nil
}

func createTestWatch(t *testing.T, policyName, watchName string, assignParams func(watchParams xrayApi.WatchParams) xrayApi.WatchParams) (string, func()) {
	xrayManager, err := xray.CreateXrayServiceManager(configTests.XrDetails)
	require.NoError(t, err)
	// Create new default watch.
	watchParams := assignParams(xrayApi.NewWatchParams())
	watchParams.Name = fmt.Sprintf("%s-%s-%s", watchName, *configTests.CiRunId, strconv.FormatInt(time.Now().Unix(), 10))
	watchParams.Active = true
	// Assign the policy to the watch.
	watchParams.Policies = []xrayApi.AssignedPolicy{
		{
			Name: policyName,
			Type: string(xrayApi.Security),
		},
	}
	assert.NoError(t, xrayManager.CreateWatch(watchParams))
	return watchParams.Name, func() {
		assert.NoError(t, xrayManager.DeleteWatch(watchParams.Name))
	}
}

func CreateWatchOnProjectBuilds(t *testing.T, policyName, watchName, projectKey string) (string, func()) {
	return createTestWatch(t, policyName, watchName, func(watchParams xrayApi.WatchParams) xrayApi.WatchParams {
		watchParams.ProjectKey = projectKey
		watchParams.Builds.Type = xrayApi.WatchBuildAll
		return watchParams
	})
}

func CreateWatchOnGitResources(t *testing.T, policyName, watchName string, gitResources ...string) (string, func()) {
	return createTestWatch(t, policyName, watchName, func(watchParams xrayApi.WatchParams) xrayApi.WatchParams {
		watchParams.GitRepositories.Resources = gitResources
		return watchParams
	})
}

func CreateWatchOnArtifactoryRepos(t *testing.T, policyName, watchName string, repos ...string) (string, func()) {
	return createTestWatch(t, policyName, watchName, func(watchParams xrayApi.WatchParams) xrayApi.WatchParams {
		watchParams.Repositories.Type = xrayApi.WatchRepositoriesByName
		for _, repo := range repos {
			watchParams.Repositories.Repositories[repo] = xrayApi.NewWatchRepositoryByName(repo)
		}
		if len(repos) == 0 {
			watchParams.Repositories.Type = xrayApi.WatchRepositoriesAll
		}
		return watchParams
	})
}

func CreateWatchOnAllBuilds(t *testing.T, policyName, watchName string) (string, func()) {
	return createTestWatch(t, policyName, watchName, func(watchParams xrayApi.WatchParams) xrayApi.WatchParams {
		watchParams.Builds.Type = xrayApi.WatchBuildAll
		return watchParams
	})
}

func CreateTestPolicyAndWatch(t *testing.T, policyName, watchName string, severity xrayApi.Severity) (string, func()) {
	xrayManager, err := xray.CreateXrayServiceManager(configTests.XrDetails)
	require.NoError(t, err)
	// Create new default policy.
	policyParams := xrayApi.PolicyParams{
		Name: fmt.Sprintf("%s-%s-%s", policyName, *configTests.CiRunId, strconv.FormatInt(time.Now().Unix(), 10)),
		Type: xrayApi.Security,
		Rules: []xrayApi.PolicyRule{{
			Name:     "sec_rule",
			Criteria: *xrayApi.CreateSeverityPolicyCriteria(severity, false),
			Priority: 1,
			Actions: &xrayApi.PolicyAction{
				FailBuild: clientUtils.Pointer(true),
			},
		}},
	}
	if !assert.NoError(t, xrayManager.CreatePolicy(policyParams)) {
		return "", func() {}
	}
	// Create new default watch.
	watchName, cleanUpWatch := CreateWatchOnAllBuilds(t, policyParams.Name, watchName)
	return watchName, func() {
		cleanUpWatch()
		assert.NoError(t, xrayManager.DeletePolicy(policyParams.Name))
	}
}

func CreateTestProjectInTempDir(t *testing.T, projectPath string) (string, func()) {
	tempDirPath, err := fileutils.CreateTempDir()
	assert.NoError(t, err, "Couldn't create temp dir")
	// Make sure the name of the final dir is the name of the project Path
	actualPath := filepath.Join(tempDirPath, filepath.Base(projectPath))
	assert.NoError(t, fileutils.CreateDirIfNotExist(actualPath))
	// Copy the project to the temp dir.
	assert.NoError(t, biutils.CopyDir(projectPath, actualPath, true, nil))
	return actualPath, func() {
		assert.NoError(t, fileutils.RemoveTempDir(tempDirPath), "Couldn't remove temp dir")
	}
}

func CreateTestProjectEnvAndChdir(t *testing.T, projectPath string) (string, func()) {
	tempDirPath, createTempDirCallback := CreateTestProjectInTempDir(t, projectPath)
	cleanCwd := ChangeWDWithCallback(t, tempDirPath)
	return tempDirPath, func() {
		cleanCwd()
		createTempDirCallback()
	}
}

// 'projectPath' directory should contains a single zip file in the format: fmt.Sprintf("%s.zip", filepath.Base(projectPath))
func CreateTestProjectFromZip(t *testing.T, projectPath string) (string, func()) {
	tempDirWithZip, cleanUp := CreateTestProjectInTempDir(t, projectPath)
	zipName := fmt.Sprintf("%s.zip", filepath.Base(projectPath))
	assert.NoError(t, clientUtils.ExtractArchive(tempDirWithZip, zipName, zipName, "", false))
	return tempDirWithZip, cleanUp
}

// 'projectPath' directory should contains a single zip file in the format: fmt.Sprintf("%s.zip", filepath.Base(projectPath))
func CreateTestProjectFromZipAndChdir(t *testing.T, projectPath string) (string, func()) {
	tempDirPath, createTempDirCallback := CreateTestProjectFromZip(t, projectPath)
	cleanCwd := ChangeWDWithCallback(t, tempDirPath)
	return tempDirPath, func() {
		cleanCwd()
		createTempDirCallback()
	}
}

// Make sure to call this function before running any tests that require the analyzer manager binary.
func PrepareAnalyzerManagerResource() (err error) {
	if localPath := os.Getenv(configTests.TestJfrogLocalAnalyzerManagerDirEnvVar); localPath != "" {
		amLocalPath, err := jas.GetAnalyzerManagerDirAbsolutePath()
		if err != nil {
			return fmt.Errorf("failed to get analyzer manager local path: %w", err)
		}
		if exist, err := fileutils.IsDirExists(amLocalPath, false); err != nil || exist {
			return err
		}
		if err := biutils.CopyDir(localPath, amLocalPath, true, []string{}); err != nil {
			return fmt.Errorf("failed to copy analyzer manager from %s to %s: %w", localPath, amLocalPath, err)
		}
		return nil
	}
	return jas.DownloadAnalyzerManagerIfNeeded(0)
}

func PrepareIndexerAppResource(details *config.ServerDetails) (err error) {
	manager, version, err := xrayUtils.CreateXrayServiceManagerAndGetVersion(details)
	if err != nil {
		return fmt.Errorf("failed to create Xray service manager: %w", err)
	}
	_, err = indexer.DownloadIndexerIfNeeded(manager, version)
	return err
}

func PrepareXrayScanLibResource() (err error) {
	return plugin.DownloadXrayLibPluginIfNeeded()
}
