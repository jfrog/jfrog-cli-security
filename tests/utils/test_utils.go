package utils

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/owenrumney/go-sarif/v2/sarif"

	clientUtils "github.com/jfrog/jfrog-client-go/utils"
	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"
	"github.com/stretchr/testify/require"

	"github.com/jfrog/gofrog/version"
	"github.com/jfrog/jfrog-cli-core/v2/plugins/components"
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"github.com/jfrog/jfrog-cli-core/v2/utils/xray"
	configTests "github.com/jfrog/jfrog-cli-security/tests"
	"github.com/stretchr/testify/assert"

	coreTests "github.com/jfrog/jfrog-cli-core/v2/utils/tests"
	"github.com/jfrog/jfrog-client-go/utils/io/fileutils"
	"github.com/jfrog/jfrog-client-go/utils/log"
	clientTests "github.com/jfrog/jfrog-client-go/utils/tests"
)

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

func InitSecurityTest(t *testing.T, xrayMinVersion string) {
	if !*configTests.TestSecurity {
		t.Skip("Skipping Security test. To run Security test add the '-test.security=true' option.")
	}
	ValidateXrayVersion(t, xrayMinVersion)
}

func ValidateXrayVersion(t *testing.T, minVersion string) {
	xrayVersion, err := getTestsXrayVersion()
	if err != nil {
		assert.NoError(t, err)
		return
	}
	err = clientUtils.ValidateMinimumVersion(clientUtils.Xray, xrayVersion.GetVersion(), minVersion)
	if err != nil {
		t.Skip(err)
	}
}

func ValidateXscVersion(t *testing.T, minVersion string) {
	xscVersion, err := getTestsXscVersion()
	if err != nil {
		t.Skip(err)
	}
	err = clientUtils.ValidateMinimumVersion(clientUtils.Xsc, xscVersion.GetVersion(), minVersion)
	if err != nil {
		t.Skip(err)
	}
}

func InitTestWithMockCommandOrParams(t *testing.T, mockCommands ...func() components.Command) (mockCli *coreTests.JfrogCli, cleanUp func()) {
	oldHomeDir := os.Getenv(coreutils.HomeDir)
	// Create server config to use with the command.
	CreateJfrogHomeConfig(t, true)
	// Create mock cli with the mock commands.
	commands := []components.Command{}
	for _, mockCommand := range mockCommands {
		commands = append(commands, mockCommand())
	}
	return GetTestCli(components.CreateEmbeddedApp("security", commands)), func() {
		clientTests.SetEnvAndAssert(t, coreutils.HomeDir, oldHomeDir)
	}
}

func GetTestResourcesPath() string {
	dir, _ := os.Getwd()
	return filepath.ToSlash(dir + "/tests/testdata/")
}

func CleanTestsHomeEnv() {
	os.Unsetenv(coreutils.HomeDir)
	CleanFileSystem()
}

func CleanFileSystem() {
	removeDirs(configTests.Out, configTests.Temp)
}

func removeDirs(dirs ...string) {
	for _, dir := range dirs {
		isExist, err := fileutils.IsDirExists(dir, false)
		if err != nil {
			log.Error(err)
		}
		if isExist {
			err = fileutils.RemoveTempDir(dir)
			if err != nil {
				log.Error(errors.New("Cannot remove path: " + dir + " due to: " + err.Error()))
			}
		}
	}
}

func getTestsXrayVersion() (version.Version, error) {
	xrayVersion, err := configTests.XrAuth.GetVersion()
	return *version.NewVersion(xrayVersion), err
}

func getTestsXscVersion() (version.Version, error) {
	xscVersion, err := configTests.XscAuth.GetVersion()
	return *version.NewVersion(xscVersion), err
}

func ChangeWD(t *testing.T, newPath string) string {
	prevDir, err := os.Getwd()
	assert.NoError(t, err, "Failed to get current dir")
	clientTests.ChangeDirAndAssert(t, newPath)
	return prevDir
}

func ReadCmdScanResults(t *testing.T, path string) *results.SecurityCommandResults {
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	var cmdResults *results.SecurityCommandResults
	if !assert.NoError(t, json.Unmarshal(content, &cmdResults)) {
		return &results.SecurityCommandResults{}
	}
	// replace paths separators
	for _, targetResults := range cmdResults.Targets {
		targetResults.Target = filepath.FromSlash(targetResults.Target)
		if targetResults.ScaResults != nil {
			for i, descriptor := range targetResults.ScaResults.Descriptors {
				targetResults.ScaResults.Descriptors[i] = filepath.FromSlash(descriptor)
			}
		}
		if targetResults.JasResults != nil {
			convertSarifRunPathsForOS(targetResults.JasResults.ApplicabilityScanResults...)
			convertSarifRunPathsForOS(targetResults.JasResults.SecretsScanResults...)
			convertSarifRunPathsForOS(targetResults.JasResults.IacScanResults...)
			convertSarifRunPathsForOS(targetResults.JasResults.SastScanResults...)
		}
	}
	return cmdResults
}

func convertSarifRunPathsForOS(runs ...*sarif.Run) {
	for _, run := range runs {
		for _, invocation := range run.Invocations {
			if invocation.WorkingDirectory != nil && invocation.WorkingDirectory.URI != nil {
				*invocation.WorkingDirectory.URI = filepath.FromSlash(sarifutils.GetInvocationWorkingDirectory(invocation))
			}
		}
		for _, result := range run.Results {
			for _, location := range result.Locations {
				if location != nil && location.PhysicalLocation != nil && location.PhysicalLocation.ArtifactLocation != nil && location.PhysicalLocation.ArtifactLocation.URI != nil {
					*location.PhysicalLocation.ArtifactLocation.URI = getJasConvertedPath(sarifutils.GetLocationFileName(location))
				}
			}
			for _, codeFlow := range result.CodeFlows {
				for _, threadFlows := range codeFlow.ThreadFlows {
					for _, location := range threadFlows.Locations {
						if location != nil && location.Location != nil && location.Location.PhysicalLocation != nil && location.Location.PhysicalLocation.ArtifactLocation != nil && location.Location.PhysicalLocation.ArtifactLocation.URI != nil {
							*location.Location.PhysicalLocation.ArtifactLocation.URI = getJasConvertedPath(sarifutils.GetLocationFileName(location.Location))
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
	if !assert.NoError(t, json.Unmarshal(content, &results)) {
		return formats.SimpleJsonResults{}
	}
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
	for _, secret := range results.Secrets {
		convertJasSimpleJsonPathsForOS(&secret)
	}
	for _, sast := range results.Sast {
		convertJasSimpleJsonPathsForOS(&sast)
	}
	for _, iac := range results.Iacs {
		convertJasSimpleJsonPathsForOS(&iac)
	}
	return results
}

func convertJasSimpleJsonPathsForOS(jas *formats.SourceCodeRow) {
	if jas == nil {
		return
	}
	jas.Location.File = getJasConvertedPath(jas.Location.File)
	if jas.Applicability != nil {
		for _, evidence := range jas.Applicability.Evidence {
			evidence.Location.File = getJasConvertedPath(evidence.Location.File)
		}
	}
	for _, codeFlow := range jas.CodeFlow {
		for _, location := range codeFlow {
			location.File = getJasConvertedPath(location.File)
		}
	}
}

func convertScaSimpleJsonPathsForOS(potentialComponents *[]formats.ComponentRow, potentialImpactPaths *[][]formats.ComponentRow, potentialImpactedDependencyDetails *formats.ImpactedDependencyDetails, potentialCves *[]formats.CveRow) {
	if potentialComponents != nil {
		components := *potentialComponents
		for _, component := range components {
			if component.Location != nil {
				component.Location.File = filepath.FromSlash(component.Location.File)
			}
		}
	}
	if potentialImpactPaths != nil {
		impactPaths := *potentialImpactPaths
		for _, impactPath := range impactPaths {
			for _, pathComponent := range impactPath {
				if pathComponent.Location != nil {
					pathComponent.Location.File = filepath.FromSlash(pathComponent.Location.File)
				}
			}
		}
	}
	if potentialImpactedDependencyDetails != nil {
		impactedDependencyDetails := *potentialImpactedDependencyDetails
		for _, component := range impactedDependencyDetails.Components {
			if component.Location != nil {
				component.Location.File = filepath.FromSlash(component.Location.File)
			}
		}
	}
	if potentialCves != nil {
		cves := *potentialCves
		for _, cve := range cves {
			if cve.Applicability != nil {
				for _, evidence := range cve.Applicability.Evidence {
					evidence.Location.File = filepath.FromSlash(evidence.Location.File)
				}
			}
		}
	}
	printCve(potentialCves)
}

func printCve(potentialCves *[]formats.CveRow) {
	for _, cve := range *potentialCves {
		cveId := cve.Id
		applicability := cve.Applicability
		log.Output(fmt.Sprintf("Cve: %v, Applicability: %v", cveId, applicability))
	}
}

func ReadSarifResults(t *testing.T, path string) *sarif.Report {
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	var results *sarif.Report
	if !assert.NoError(t, json.Unmarshal(content, &results)) {
		return &sarif.Report{}
	}
	// replace paths separators
	convertSarifRunPathsForOS(results.Runs...)
	return results
}

func ReadSummaryResults(t *testing.T, path string) formats.ResultsSummary {
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	var results formats.ResultsSummary
	if !assert.NoError(t, json.Unmarshal(content, &results)) {
		return formats.ResultsSummary{}
	}
	// replace paths separators
	for _, targetResults := range results.Scans {
		targetResults.Target = filepath.FromSlash(targetResults.Target)
	}
	return results
}

func getJasConvertedPath(pathToConvert string) string {
	return filepath.FromSlash(strings.TrimPrefix(pathToConvert, "file://"))
}

func CreateTestWatch(t *testing.T, policyName string, watchName, severity xrayUtils.Severity) (string, func()) {
	xrayManager, err := xray.CreateXrayServiceManager(configTests.XrDetails)
	require.NoError(t, err)
	// Create new default policy.
	policyParams := xrayUtils.PolicyParams{
		Name: fmt.Sprintf("%s-%s", policyName, strconv.FormatInt(time.Now().Unix(), 10)),
		Type: xrayUtils.Security,
		Rules: []xrayUtils.PolicyRule{{
			Name:     "sec_rule",
			Criteria: *xrayUtils.CreateSeverityPolicyCriteria(severity),
			Priority: 1,
			Actions: &xrayUtils.PolicyAction{
				FailBuild: clientUtils.Pointer(true),
			},
		}},
	}
	if !assert.NoError(t, xrayManager.CreatePolicy(policyParams)) {
		return "", func() {}
	}
	// Create new default watch.
	watchParams := xrayUtils.NewWatchParams()
	watchParams.Name = fmt.Sprintf("%s-%s", watchName, strconv.FormatInt(time.Now().Unix(), 10))
	watchParams.Active = true
	watchParams.Builds.Type = xrayUtils.WatchBuildAll
	watchParams.Policies = []xrayUtils.AssignedPolicy{
		{
			Name: policyParams.Name,
			Type: "security",
		},
	}
	assert.NoError(t, xrayManager.CreateWatch(watchParams))
	return watchParams.Name, func() {
		assert.NoError(t, xrayManager.DeleteWatch(watchParams.Name))
		assert.NoError(t, xrayManager.DeletePolicy(policyParams.Name))
	}
}
