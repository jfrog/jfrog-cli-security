package conversion

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
	"github.com/jfrog/jfrog-client-go/xray/services"

	testUtils "github.com/jfrog/jfrog-cli-security/tests/utils"
	"github.com/jfrog/jfrog-cli-security/tests/validations"
	"github.com/jfrog/jfrog-cli-security/utils/results"

	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"
	"github.com/stretchr/testify/assert"
)

var (
	testDataDir = filepath.Join("..", "..", "..", "tests", "testdata", "output")
)

const (
	SimpleJson conversionFormat = "simple-json"
	Sarif      conversionFormat = "sarif"
	Summary    conversionFormat = "summary"
)

type conversionFormat string

func TestConvertResults(t *testing.T) {
	testCases := []struct {
		cmdType             utils.CommandType
		contentFormat       conversionFormat
		expectedContentPath string
	}{
		{
			cmdType:             utils.SourceCode,
			contentFormat:       SimpleJson,
			expectedContentPath: filepath.Join(testDataDir, "audit", "audit_simple_json.json"),
		},
		{
			cmdType:             utils.SourceCode,
			contentFormat:       Sarif,
			expectedContentPath: filepath.Join(testDataDir, "audit", "audit_sarif.json"),
		},
		{
			cmdType:             utils.SourceCode,
			contentFormat:       Summary,
			expectedContentPath: filepath.Join(testDataDir, "audit", "audit_summary.json"),
		},
		{
			cmdType:             utils.DockerImage,
			contentFormat:       SimpleJson,
			expectedContentPath: filepath.Join(testDataDir, "dockerscan", "docker_simple_json.json"),
		},
		{
			cmdType:             utils.DockerImage,
			contentFormat:       Sarif,
			expectedContentPath: filepath.Join(testDataDir, "dockerscan", "docker_sarif.json"),
		},
		{
			cmdType:             utils.DockerImage,
			contentFormat:       Summary,
			expectedContentPath: filepath.Join(testDataDir, "dockerscan", "docker_summary.json"),
		},
	}

	for _, testCase := range testCases {
		t.Run(fmt.Sprintf("%s convert to %s", testCase.cmdType, testCase.contentFormat), func(t *testing.T) {
			var validationParams validations.ValidationParams
			var inputResults *results.SecurityCommandResults
			switch testCase.cmdType {
			case utils.SourceCode:
				inputResults, validationParams = getAuditTestResults(testCase.contentFormat == Summary)
			case utils.DockerImage:
				inputResults, validationParams = getDockerScanTestResults(testCase.contentFormat == Summary)
			default:
				t.Fatalf("Unsupported command type: %s", testCase.cmdType)
			}
			pretty := false
			if testCase.contentFormat == Sarif {
				pretty = true
			}
			convertor := NewCommandResultsConvertor(ResultConvertParams{IncludeVulnerabilities: true, HasViolationContext: true, IncludeLicenses: true, Pretty: pretty})

			switch testCase.contentFormat {
			case SimpleJson:
				validateSimpleJsonConversion(t, testUtils.ReadSimpleJsonResults(t, testCase.expectedContentPath), inputResults, convertor, validationParams)
			case Sarif:
				validateSarifConversion(t, testUtils.ReadSarifResults(t, testCase.expectedContentPath), inputResults, convertor, validationParams)
			case Summary:
				validateSummaryConversion(t, testUtils.ReadSummaryResults(t, testCase.expectedContentPath), inputResults, convertor, validationParams)
			}
		})
	}
}

func validateSimpleJsonConversion(t *testing.T, expectedResults formats.SimpleJsonResults, inputResults *results.SecurityCommandResults, convertor *CommandResultsConvertor, validationParams validations.ValidationParams) {
	validationParams.Expected = expectedResults

	actualResults, err := convertor.ConvertToSimpleJson(inputResults)
	if !assert.NoError(t, err) {
		return
	}
	validationParams.Actual = actualResults

	validations.ValidateCommandSimpleJsonOutput(t, validationParams)
}

func validateSarifConversion(t *testing.T, expectedResults *sarif.Report, inputResults *results.SecurityCommandResults, convertor *CommandResultsConvertor, validationParams validations.ValidationParams) {
	validationParams.Expected = expectedResults

	actualResults, err := convertor.ConvertToSarif(inputResults)
	if !assert.NoError(t, err) {
		return
	}
	validationParams.Actual = actualResults

	validations.ValidateSarifIssuesCount(t, validationParams, actualResults)
}

func validateSummaryConversion(t *testing.T, expectedResults formats.ResultsSummary, inputResults *results.SecurityCommandResults, convertor *CommandResultsConvertor, validationParams validations.ValidationParams) {
	validationParams.Expected = expectedResults

	actualResults, err := convertor.ConvertToSummary(inputResults)
	if !assert.NoError(t, err) {
		return
	}
	validationParams.Actual = actualResults

	validations.ValidateCommandSummaryOutput(t, validationParams)
}

func getAuditTestResults(unique bool) (*results.SecurityCommandResults, validations.ValidationParams) {
	expected := validations.ValidationParams{
		ExactResultsMatch: true,
		Total:             &validations.TotalCount{Violations: 7, Licenses: 1},
		Violations: &validations.ViolationCount{
			ValidateScan:                &validations.ScanCount{Sca: 3, Sast: 2, Secrets: 2},
			ValidateApplicabilityStatus: &validations.ApplicabilityStatusCount{Applicable: 1, NotCovered: 1},
		},
	}
	if unique {
		// Only count CVE findings, not impacted components
		expected.Total.Vulnerabilities = 7
		expected.Vulnerabilities = &validations.VulnerabilityCount{
			ValidateScan:                &validations.ScanCount{Sca: 4, Iac: 1, Secrets: 2},
			ValidateApplicabilityStatus: &validations.ApplicabilityStatusCount{Applicable: 1, NotApplicable: 2, NotCovered: 1},
		}
	} else {
		// Count all findings (pair of issueId+impactedComponent)
		expected.Total.Vulnerabilities = 8
		expected.Vulnerabilities = &validations.VulnerabilityCount{
			ValidateScan:                &validations.ScanCount{Sca: 5, Iac: 1, Secrets: 2},
			ValidateApplicabilityStatus: &validations.ApplicabilityStatusCount{Applicable: 1, NotApplicable: 3, NotCovered: 1},
		}
	}
	// Create basic command results to be converted to different formats
	cmdResults := results.NewCommandResults(utils.SourceCode)
	cmdResults.SetEntitledForJas(true).SetXrayVersion("3.107.13").SetXscVersion("1.12.5").SetMultiScanId("7d5e4733-3f93-11ef-8147-e610d09d7daa")
	npmTargetResults := cmdResults.NewScanResults(results.ScanTarget{Target: filepath.Join("Users", "user", "project-with-issues"), Technology: techutils.Npm}).SetDescriptors(filepath.Join("Users", "user", "project-with-issues", "package.json"))
	// SCA scan results
	npmTargetResults.NewScaScanResults(0, results.Sbom{}, services.ScanResponse{
		ScanId: "711851ce-68c4-4dfd-7afb-c29737ebcb96",
		Vulnerabilities: []services.Vulnerability{
			{
				Cves: []services.Cve{{
					Id: "CVE-2024-39249",
				}},
				Summary:  "Async vulnerable to ReDoS",
				Severity: severityutils.Unknown.String(),
				Components: map[string]services.Component{
					"npm://async:3.2.4": {
						ImpactPaths: [][]services.ImpactPathNode{{
							{ComponentId: "npm://froghome:1.0.0"},
							{ComponentId: "npm://jake:10.8.7"},
							{ComponentId: "npm://async:3.2.4"},
						}},
					},
				},
				IssueId: "XRAY-609848",
				ExtendedInformation: &services.ExtendedInformation{
					ShortDescription:      "ReDoS in Async may lead to denial of service while parsing",
					JfrogResearchSeverity: "Low",
					JfrogResearchSeverityReasons: []services.JfrogResearchSeverityReason{
						{Name: "The reported CVSS was either wrongly calculated", Description: "The reported CVSS does not reflect the severity of the vulnerability", IsPositive: true},
					},
				},
				References: []string{"https://github.com/zunak/CVE-2024-39249", "https://nvd.nist.gov/vuln/detail/CVE-2024-39249"},
			},
			{
				Cves: []services.Cve{{
					Id:          "CVE-2020-8203",
					CvssV2Score: "5.8",
					CvssV3Score: "7.4",
				}},
				Summary:  "Code Injection",
				Severity: severityutils.High.String(),
				Components: map[string]services.Component{
					"npm://lodash:4.17.0": {
						ImpactPaths: [][]services.ImpactPathNode{{
							{ComponentId: "npm://froghome:1.0.0"},
							{ComponentId: "npm://lodash:4.17.0"},
						}},
						FixedVersions: []string{"[4.17.19]"},
					},
					"npm://ejs:3.1.6": {
						ImpactPaths: [][]services.ImpactPathNode{{
							{ComponentId: "npm://froghome:1.0.0"},
							{ComponentId: "npm://lodash:4.17.0"},
							{ComponentId: "npm://ejs:3.1.6"},
						}},
						FixedVersions: []string{"[3.1.7]"},
					},
				},
				IssueId:             "XRAY-114089",
				ExtendedInformation: &services.ExtendedInformation{JfrogResearchSeverity: "Low"},
			},
			{
				Cves: []services.Cve{{
					Id: "CVE-2018-16487",
				}},
				Summary:  "Prototype Pollution",
				Severity: severityutils.Medium.String(),
				Components: map[string]services.Component{
					"npm://lodash:4.17.0": {
						ImpactPaths: [][]services.ImpactPathNode{{
							{ComponentId: "npm://froghome:1.0.0"},
							{ComponentId: "npm://lodash:4.17.0"},
						}},
						FixedVersions: []string{"[4.17.11]"},
					},
				},
				IssueId:             "XRAY-75300",
				ExtendedInformation: &services.ExtendedInformation{Remediation: "Some remediation"},
			},
			{
				Cves: []services.Cve{{
					Id: "CVE-2018-3721",
				}},
				Summary:  "Improperly Controlled Modification of Object",
				Severity: severityutils.Medium.String(),
				Components: map[string]services.Component{
					"npm://lodash:4.17.0": {
						ImpactPaths: [][]services.ImpactPathNode{{
							{ComponentId: "npm://froghome:1.0.0"},
							{ComponentId: "npm://lodash:4.17.0"},
						}},
						FixedVersions: []string{"[4.17.5]"},
					},
				},
				IssueId: "XRAY-72918",
			},
		},
		Violations: []services.Violation{
			{
				ViolationType: utils.ViolationTypeSecurity.String(),
				Cves: []services.Cve{{
					Id: "CVE-2024-39249",
				}},
				Summary:  "Async vulnerable to ReDoS",
				Severity: severityutils.Unknown.String(),
				Components: map[string]services.Component{
					"npm://async:3.2.4": {
						ImpactPaths: [][]services.ImpactPathNode{{
							{ComponentId: "npm://froghome:1.0.0"},
							{ComponentId: "npm://jake:10.8.7"},
							{ComponentId: "npm://async:3.2.4"},
						}},
					},
				},
				WatchName:           "security-watch",
				Policies:            []services.Policy{{Policy: "npm-security"}},
				IssueId:             "XRAY-609848",
				ExtendedInformation: &services.ExtendedInformation{JfrogResearchSeverity: "Low"},
			},
			{
				ViolationType: utils.ViolationTypeSecurity.String(),
				Cves: []services.Cve{{
					Id: "CVE-2018-3721",
				}},
				Summary:  "Improperly Controlled Modification of Object",
				Severity: severityutils.Medium.String(),
				Components: map[string]services.Component{
					"npm://lodash:4.17.0": {
						ImpactPaths: [][]services.ImpactPathNode{{
							{ComponentId: "npm://froghome:1.0.0"},
							{ComponentId: "npm://lodash:4.17.0"},
						}},
						FixedVersions: []string{"[4.17.5]"},
					},
				},
				WatchName: "security-watch",
				Policies:  []services.Policy{{Policy: "npm-security"}},
				IssueId:   "XRAY-72918",
			},
			{
				ViolationType: utils.ViolationTypeLicense.String(),
				LicenseKey:    "MIT",
				LicenseName:   "MIT full name",
				Severity:      severityutils.High.String(),
				Components: map[string]services.Component{
					"npm://lodash:4.17.0": {
						ImpactPaths: [][]services.ImpactPathNode{{
							{ComponentId: "npm://froghome:1.0.0"},
							{ComponentId: "npm://lodash:4.17.0"},
						}},
					},
				},
				WatchName: "license-watch",
				Policies:  []services.Policy{{Policy: "npm-license"}},
				IssueId:   "MIT",
			},
		},
		Licenses: []services.License{
			{
				Key:  "MIT",
				Name: "MIT full name",
				Components: map[string]services.Component{
					"npm://lodash:4.17.0": {
						ImpactPaths: [][]services.ImpactPathNode{{
							{ComponentId: "npm://froghome:1.0.0"},
							{ComponentId: "npm://lodash:4.17.0"},
						}},
					},
				},
			},
		},
		ScannedStatus: "completed",
	})
	// Contextual analysis scan results
	npmTargetResults.JasResults.AddApplicabilityScanResults(0,
		&sarif.Run{
			Tool: sarif.Tool{
				Driver: sarifutils.CreateDummyDriver(validations.ContextualAnalysisToolName,
					validations.CreateDummyApplicabilityRule("CVE-2024-39249", "applicable"),
					validations.CreateDummyApplicabilityRule("CVE-2018-16487", "not_applicable"),
					validations.CreateDummyApplicabilityRule("CVE-2020-8203", "not_applicable"),
					validations.CreateDummyApplicabilityRule("CVE-2018-3721", "not_covered"),
				),
			},
			Invocations: []*sarif.Invocation{sarif.NewInvocation().WithWorkingDirectory(sarif.NewSimpleArtifactLocation(filepath.Join("Users", "user", "project-with-issues")))},
			Results: []*sarif.Result{
				validations.CreateDummyApplicableResults("CVE-2024-39249", formats.Location{File: filepath.Join("Users", "user", "project-with-issues", "file-A"), StartLine: 1, StartColumn: 2, EndLine: 3, EndColumn: 4, Snippet: "snippet"}),
				validations.CreateDummyApplicableResults("CVE-2024-39249", formats.Location{File: filepath.Join("Users", "user", "project-with-issues", "file-B"), StartLine: 1, StartColumn: 2, EndLine: 3, EndColumn: 4, Snippet: "snippet2"}),
				// Not Applicable result = remediation location, not a finding add for test confirmation
				validations.CreateDummyApplicableResults("CVE-2018-16487", formats.Location{File: filepath.Join("Users", "user", "project-with-issues", "file-C"), StartLine: 1, StartColumn: 2, EndLine: 3, EndColumn: 4, Snippet: "snippet3"}),
			},
		},
	)
	// Iac scan results
	npmTargetResults.JasResults.AddJasScanResults(jasutils.IaC,
		[]*sarif.Run{{
			Tool:        sarif.Tool{Driver: sarifutils.CreateDummyDriver(validations.IacToolName, validations.CreateDummyJasRule("aws_cloudfront_tls_only"))},
			Invocations: []*sarif.Invocation{sarif.NewInvocation().WithWorkingDirectory(sarif.NewSimpleArtifactLocation(filepath.Join("Users", "user", "project-with-issues")))},
			Results: []*sarif.Result{
				validations.CreateDummyJasResult("aws_cloudfront_tls_only", severityutils.LevelError, formats.Location{File: filepath.Join("Users", "user", "project-with-issues", "req_sw_terraform_aws_cloudfront_tls_only.tf"), StartLine: 2, StartColumn: 1, EndLine: 21, EndColumn: 1, Snippet: "viewer_protocol_policy..."}),
			},
		}},
		// No Violations
		[]*sarif.Run{}, 0,
	)
	// Secrets scan results
	npmTargetResults.JasResults.AddJasScanResults(jasutils.Secrets,
		[]*sarif.Run{{
			Tool:        sarif.Tool{Driver: sarifutils.CreateDummyDriver(validations.SecretsToolName, validations.CreateDummyJasRule("REQ.SECRET.KEYS"))},
			Invocations: []*sarif.Invocation{sarif.NewInvocation().WithWorkingDirectory(sarif.NewSimpleArtifactLocation(filepath.Join("Users", "user", "project-with-issues")))},
			Results: []*sarif.Result{
				validations.CreateDummySecretResult("REQ.SECRET.KEYS", jasutils.Active, "active token", formats.Location{File: filepath.Join("Users", "user", "project-with-issues", "fake-creds.txt"), StartLine: 2, StartColumn: 1, EndLine: 2, EndColumn: 11, Snippet: "Sqc************"}),
				validations.CreateDummySecretResult("REQ.SECRET.KEYS", jasutils.NotAToken, "", formats.Location{File: filepath.Join("Users", "user", "project-with-issues", "dir", "server.js"), StartLine: 3, StartColumn: 1, EndLine: 3, EndColumn: 11, Snippet: "gho************"}),
			},
		}},
		[]*sarif.Run{{
			Tool:        sarif.Tool{Driver: sarifutils.CreateDummyDriver(validations.SecretsToolName, validations.CreateDummyJasRule("REQ.SECRET.KEYS"))},
			Invocations: []*sarif.Invocation{sarif.NewInvocation().WithWorkingDirectory(sarif.NewSimpleArtifactLocation(filepath.Join("Users", "user", "project-with-issues")))},
			Results: []*sarif.Result{
				validations.CreateDummySecretViolationResult("REQ.SECRET.KEYS", jasutils.Active, "active token", "watch", "sec-violation-1", []string{"policy"}, formats.Location{File: filepath.Join("Users", "user", "project-with-issues", "fake-creds.txt"), StartLine: 2, StartColumn: 1, EndLine: 2, EndColumn: 11, Snippet: "Sqc************"}),
				validations.CreateDummySecretViolationResult("REQ.SECRET.KEYS", jasutils.NotAToken, "", "watch", "sec-violation-2", []string{"policy"}, formats.Location{File: filepath.Join("Users", "user", "project-with-issues", "server.js"), StartLine: 3, StartColumn: 1, EndLine: 3, EndColumn: 11, Snippet: "gho************"}),
			},
		}}, 0,
	)
	// Sast scan results
	npmTargetResults.JasResults.AddJasScanResults(jasutils.Sast,
		// No Vulnerabilities
		[]*sarif.Run{{
			Tool:        sarif.Tool{Driver: sarifutils.CreateDummyDriver(validations.SastToolName, validations.CreateDummyJasRule("aws_cloudfront_tls_only"))},
			Invocations: []*sarif.Invocation{sarif.NewInvocation().WithWorkingDirectory(sarif.NewSimpleArtifactLocation(filepath.Join("Users", "user", "project-with-issues")))},
		}},
		[]*sarif.Run{{
			Tool:        sarif.Tool{Driver: sarifutils.CreateDummyDriver(validations.SastToolName, validations.CreateDummyJasRule("js-template-injection", "73"), validations.CreateDummyJasRule("js-insecure-random", "338"))},
			Invocations: []*sarif.Invocation{sarif.NewInvocation().WithWorkingDirectory(sarif.NewSimpleArtifactLocation(filepath.Join("Users", "user", "project-with-issues")))},
			Results: []*sarif.Result{
				validations.CreateDummySastViolationResult("js-insecure-random", severityutils.LevelNote, "watch", "sast-violation-1", []string{"policy", "policy2"}, formats.Location{File: filepath.Join("Users", "user", "project-with-issues", "public", "js", "bootstrap.bundle.js"), StartLine: 136, StartColumn: 22, EndLine: 136, EndColumn: 35, Snippet: "Math.random()"}),
				validations.CreateDummySastViolationResult("js-template-injection", severityutils.LevelError, "watch", "sast-violation-2", []string{"policy", "policy2"}, formats.Location{File: filepath.Join("Users", "user", "project-with-issues", "server.js"), StartLine: 26, StartColumn: 28, EndLine: 26, EndColumn: 37, Snippet: "req.query"},
					[]formats.Location{
						{File: "/Users/user/project-with-issues/server.js", StartLine: 27, StartColumn: 28, EndLine: 26, EndColumn: 31, Snippet: "req"},
						{File: "/Users/user/project-with-issues/server.js", StartLine: 26, StartColumn: 28, EndLine: 26, EndColumn: 37, Snippet: "req.query"},
					},
				),
			},
		}},
		0,
	)
	return cmdResults, expected
}

func getDockerScanTestResults(unique bool) (*results.SecurityCommandResults, validations.ValidationParams) {
	expected := validations.ValidationParams{
		ExactResultsMatch: true,
		Total:             &validations.TotalCount{Violations: 2},
		Violations: &validations.ViolationCount{
			ValidateScan:                &validations.ScanCount{Sca: 1, Secrets: 1},
			ValidateApplicabilityStatus: &validations.ApplicabilityStatusCount{Applicable: 1, Inactive: 1},
		},
	}
	if unique {
		// Only count CVE findings, not impacted components
		expected.Total.Vulnerabilities = 3
		expected.Vulnerabilities = &validations.VulnerabilityCount{
			ValidateScan:                &validations.ScanCount{Sca: 2, Secrets: 1},
			ValidateApplicabilityStatus: &validations.ApplicabilityStatusCount{Applicable: 1, Undetermined: 1, Inactive: 1},
		}
	} else {
		// Count all findings (pair of issueId+impactedComponent)
		expected.Total.Vulnerabilities = 4
		expected.Vulnerabilities = &validations.VulnerabilityCount{
			ValidateScan:                &validations.ScanCount{Sca: 3, Secrets: 1},
			ValidateApplicabilityStatus: &validations.ApplicabilityStatusCount{Applicable: 1, Undetermined: 2, Inactive: 1},
		}
	}
	// Create basic command results to be converted to different formats
	cmdResults := results.NewCommandResults(utils.DockerImage)
	cmdResults.SetEntitledForJas(true).SetXrayVersion("3.107.13").SetXscVersion("1.12.5").SetMultiScanId("7d5e4733-3f93-11ef-8147-e610d09d7daa")
	dockerImageTarget := cmdResults.NewScanResults(results.ScanTarget{Target: filepath.Join("temp", "folders", "T", "jfrog.cli.temp.-11-11", "image.tar"), Name: "platform.jfrog.io/swamp-docker/swamp:latest", Technology: techutils.Oci})
	// SCA scan results
	dockerImageTarget.NewScaScanResults(0, results.Sbom{}, services.ScanResponse{
		ScanId: "27da9106-88ea-416b-799b-bc7d15783473",
		Vulnerabilities: []services.Vulnerability{
			{
				Cves: []services.Cve{{
					Id: "CVE-2024-6119",
				}},
				Summary:  "Issue summary",
				Severity: severityutils.Unknown.String(),
				Components: map[string]services.Component{
					"deb://debian:bookworm:libssl3:3.0.13-1~deb12u1": {
						ImpactPaths: [][]services.ImpactPathNode{{
							{ComponentId: "docker://platform.jfrog.io/swamp-docker/swamp:latest"},
							{
								ComponentId: "generic://sha256:f21c087a3964a446bce1aa4e3ec7cf82020dd77ad14f1cf4ea49cbb32eda1595/sha256__f21c087a3964a446bce1aa4e3ec7cf82020dd77ad14f1cf4ea49cbb32eda1595.tar",
								FullPath:    "sha256__f21c087a3964a446bce1aa4e3ec7cf82020dd77ad14f1cf4ea49cbb32eda1595.tar",
							},
							{
								ComponentId: "deb://debian:bookworm:libssl3:3.0.13-1~deb12u1",
								FullPath:    "libssl3:3.0.13-1~deb12u1",
							},
						}},
					},
				},
				IssueId:             "XRAY-632747",
				ExtendedInformation: &services.ExtendedInformation{JfrogResearchSeverity: "Medium"},
			},
			{
				Cves: []services.Cve{{
					Id: "CVE-2024-38428",
				}},
				Summary:  "Interpretation Conflict",
				Severity: severityutils.Critical.String(),
				Components: map[string]services.Component{
					"deb://debian:bookworm:libssl3:3.0.13-1~deb12u1": {
						ImpactPaths: [][]services.ImpactPathNode{{
							{ComponentId: "docker://platform.jfrog.io/swamp-docker/swamp:latest"},
							{
								ComponentId: "generic://sha256:f21c087a3964a446bce1aa4e3ec7cf82020dd77ad14f1cf4ea49cbb32eda1595/sha256__f21c087a3964a446bce1aa4e3ec7cf82020dd77ad14f1cf4ea49cbb32eda1595.tar",
								FullPath:    "sha256__f21c087a3964a446bce1aa4e3ec7cf82020dd77ad14f1cf4ea49cbb32eda1595.tar",
							},
							{
								ComponentId: "deb://debian:bookworm:libssl3:3.0.13-1~deb12u1",
								FullPath:    "libssl3:3.0.13-1~deb12u1",
							},
						}},
					},
					"deb://debian:bookworm:openssl:3.0.13-1~deb12u1": {
						ImpactPaths: [][]services.ImpactPathNode{{
							{ComponentId: "docker://platform.jfrog.io/swamp-docker/swamp:latest"},
							{
								ComponentId: "generic://sha256:f21c087a3964a446bce1aa4e3ec7cf82020dd77ad14f1cf4ea49cbb32eda1595/sha256__f21c087a3964a446bce1aa4e3ec7cf82020dd77ad14f1cf4ea49cbb32eda1595.tar",
								FullPath:    "sha256__f21c087a3964a446bce1aa4e3ec7cf82020dd77ad14f1cf4ea49cbb32eda1595.tar",
							},
							{
								ComponentId: "deb://debian:bookworm:openssl:3.0.13-1~deb12u1",
								FullPath:    "openssl:3.0.13-1~deb12u1",
							},
						}},
						FixedVersions: []string{"[3.0.14-1~deb12u2]"},
					},
				},
				IssueId:             "XRAY-606103",
				ExtendedInformation: &services.ExtendedInformation{JfrogResearchSeverity: "Critical"},
			},
		},
		Violations: []services.Violation{
			{
				ViolationType: utils.ViolationTypeSecurity.String(),
				Cves: []services.Cve{{
					Id: "CVE-2024-6119",
				}},
				Summary:  "Issue summary",
				Severity: severityutils.Unknown.String(),
				Components: map[string]services.Component{
					"deb://debian:bookworm:libssl3:3.0.13-1~deb12u1": {
						ImpactPaths: [][]services.ImpactPathNode{{
							{ComponentId: "docker://platform.jfrog.io/swamp-docker/swamp:latest"},
							{
								ComponentId: "generic://sha256:f21c087a3964a446bce1aa4e3ec7cf82020dd77ad14f1cf4ea49cbb32eda1595/sha256__f21c087a3964a446bce1aa4e3ec7cf82020dd77ad14f1cf4ea49cbb32eda1595.tar",
								FullPath:    "sha256__f21c087a3964a446bce1aa4e3ec7cf82020dd77ad14f1cf4ea49cbb32eda1595.tar",
							},
							{
								ComponentId: "deb://debian:bookworm:libssl3:3.0.13-1~deb12u1",
								FullPath:    "libssl3:3.0.13-1~deb12u1",
							},
						}},
					},
				},
				IssueId:             "XRAY-632747",
				ExtendedInformation: &services.ExtendedInformation{JfrogResearchSeverity: "Medium"},
				WatchName:           "security-watch",
				Policies:            []services.Policy{{Policy: "debian-security"}},
			},
		},
		ScannedStatus: "completed",
	})
	// Contextual analysis scan results
	dockerImageTarget.JasResults.AddApplicabilityScanResults(0,
		&sarif.Run{
			Tool: sarif.Tool{
				Driver: sarifutils.CreateDummyDriver(validations.ContextualAnalysisToolName,
					validations.CreateDummyApplicabilityRule("CVE-2024-6119", "applicable"),
					validations.CreateDummyApplicabilityRule("CVE-2024-38428", "undetermined"),
				),
			},
			Invocations: []*sarif.Invocation{sarif.NewInvocation().WithWorkingDirectory(sarif.NewSimpleArtifactLocation(filepath.Join("temp", "folders", "T", "jfrog.cli.temp.-11-11")))},
			Results:     []*sarif.Result{validations.CreateDummyApplicableResults("CVE-2024-6119", formats.Location{File: "file://" + filepath.Join("usr", "local", "bin", "node")})},
		},
	)
	// Secrets scan results
	dockerImageTarget.JasResults.AddJasScanResults(jasutils.Secrets,
		[]*sarif.Run{{
			Tool:        sarif.Tool{Driver: sarifutils.CreateDummyDriver(validations.SecretsToolName, validations.CreateDummyJasRule("REQ.SECRET.GENERIC.CODE"))},
			Invocations: []*sarif.Invocation{sarif.NewInvocation().WithWorkingDirectory(sarif.NewSimpleArtifactLocation(filepath.Join("temp", "folders", "T", "jfrog.cli.temp.-11-11")))},
			Results: []*sarif.Result{
				validations.CreateDummySecretResult("REQ.SECRET.GENERIC.CODE", jasutils.Inactive, "expired", formats.Location{File: filepath.Join("temp", "folders", "T", "tmpsfyn_3d1", "unpacked", "sha256", "9e88ea9de1b44baba5e96a79e33e4af64334b2bf129e838e12f6dae71b5c86f0", "usr", "src", "app", "server", "index.js"), StartLine: 5, StartColumn: 7, EndLine: 5, EndColumn: 57, Snippet: "tok************"}),
			},
		}},
		[]*sarif.Run{{
			Tool:        sarif.Tool{Driver: sarifutils.CreateDummyDriver(validations.SecretsToolName, validations.CreateDummyJasRule("REQ.SECRET.GENERIC.CODE"))},
			Invocations: []*sarif.Invocation{sarif.NewInvocation().WithWorkingDirectory(sarif.NewSimpleArtifactLocation(filepath.Join("temp", "folders", "T", "jfrog.cli.temp.-11-11")))},
			Results: []*sarif.Result{
				validations.CreateDummySecretViolationResult("REQ.SECRET.GENERIC.CODE", jasutils.Inactive, "expired", "watch", "sec-violation-1", []string{"policy"}, formats.Location{File: filepath.Join("temp", "folders", "T", "tmpsfyn_3d1", "unpacked", "sha256", "9e88ea9de1b44baba5e96a79e33e4af64334b2bf129e838e12f6dae71b5c86f0", "usr", "src", "app", "server", "index.js"), StartLine: 5, StartColumn: 7, EndLine: 5, EndColumn: 57, Snippet: "tok************"}),
			},
		}}, 0,
	)

	return cmdResults, expected
}
