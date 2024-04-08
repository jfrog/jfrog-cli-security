package jas

import (
	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	"os"
	"testing"

	"github.com/jfrog/jfrog-cli-security/utils"
	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/stretchr/testify/assert"
)

func TestExcludeSuppressResults(t *testing.T) {
	tests := []struct {
		name           string
		sarifResults   []*sarif.Result
		expectedOutput []*sarif.Result
	}{
		{
			sarifResults: []*sarif.Result{
				utils.CreateResultWithOneLocation("", 0, 0, 0, 0, "snippet1", "ruleId1", "level1"),
				utils.CreateResultWithOneLocation("", 0, 0, 0, 0, "snippet2", "ruleId2", "level2"),
			},
			expectedOutput: []*sarif.Result{
				utils.CreateResultWithOneLocation("", 0, 0, 0, 0, "snippet1", "ruleId1", "level1"),
				utils.CreateResultWithOneLocation("", 0, 0, 0, 0, "snippet2", "ruleId2", "level2"),
			},
		},
		{
			sarifResults: []*sarif.Result{
				utils.CreateResultWithOneLocation("", 0, 0, 0, 0, "snippet1", "ruleId1", "level1").WithSuppression([]*sarif.Suppression{sarif.NewSuppression("")}),
				utils.CreateResultWithOneLocation("", 0, 0, 0, 0, "snippet2", "ruleId2", "level2"),
			},
			expectedOutput: []*sarif.Result{
				utils.CreateResultWithOneLocation("", 0, 0, 0, 0, "snippet2", "ruleId2", "level2"),
			},
		},
		{
			sarifResults: []*sarif.Result{
				utils.CreateResultWithOneLocation("", 0, 0, 0, 0, "snippet1", "ruleId1", "level1").WithSuppression([]*sarif.Suppression{sarif.NewSuppression("")}),
				utils.CreateResultWithOneLocation("", 0, 0, 0, 0, "snippet2", "ruleId2", "level2").WithSuppression([]*sarif.Suppression{sarif.NewSuppression("")}),
			},
			expectedOutput: []*sarif.Result{},
		},
	}

	for _, test := range tests {
		assert.Equal(t, test.expectedOutput, excludeSuppressResults(test.sarifResults))
	}
}

func TestAddScoreToRunRules(t *testing.T) {

	tests := []struct {
		name           string
		sarifRun       *sarif.Run
		expectedOutput []*sarif.ReportingDescriptor
	}{
		{
			sarifRun: utils.CreateRunWithDummyResults(
				utils.CreateResultWithOneLocation("file1", 0, 0, 0, 0, "snippet", "rule1", "info"),
				utils.CreateResultWithOneLocation("file2", 0, 0, 0, 0, "snippet", "rule1", "info"),
				utils.CreateResultWithOneLocation("file", 0, 0, 0, 0, "snippet", "rule2", "warning"),
			),
			expectedOutput: []*sarif.ReportingDescriptor{
				sarif.NewRule("rule1").WithProperties(sarif.Properties{"security-severity": "6.9"}),
				sarif.NewRule("rule2").WithProperties(sarif.Properties{"security-severity": "6.9"}),
			},
		},
		{
			sarifRun: utils.CreateRunWithDummyResults(
				utils.CreateResultWithOneLocation("file", 0, 0, 0, 0, "snippet", "rule1", "none"),
				utils.CreateResultWithOneLocation("file", 0, 0, 0, 0, "snippet", "rule2", "note"),
				utils.CreateResultWithOneLocation("file", 0, 0, 0, 0, "snippet", "rule3", "info"),
				utils.CreateResultWithOneLocation("file", 0, 0, 0, 0, "snippet", "rule4", "warning"),
				utils.CreateResultWithOneLocation("file", 0, 0, 0, 0, "snippet", "rule5", "error"),
			),
			expectedOutput: []*sarif.ReportingDescriptor{
				sarif.NewRule("rule1").WithProperties(sarif.Properties{"security-severity": "0.0"}),
				sarif.NewRule("rule2").WithProperties(sarif.Properties{"security-severity": "3.9"}),
				sarif.NewRule("rule3").WithProperties(sarif.Properties{"security-severity": "6.9"}),
				sarif.NewRule("rule4").WithProperties(sarif.Properties{"security-severity": "6.9"}),
				sarif.NewRule("rule5").WithProperties(sarif.Properties{"security-severity": "8.9"}),
			},
		},
	}

	for _, test := range tests {
		addScoreToRunRules(test.sarifRun)
		assert.Equal(t, test.expectedOutput, test.sarifRun.Tool.Driver.Rules)
	}
}

func TestSetAnalyticsMetricsDataForAnalyzerManager(t *testing.T) {
	type args struct {
		msi          string
		technologies []coreutils.Technology
	}
	tests := []struct {
		name string
		args args
		want func()
	}{
		{name: "One valid technology", args: args{msi: "msi", technologies: []coreutils.Technology{coreutils.Maven}}, want: func() {
			assert.Equal(t, string(coreutils.Maven), os.Getenv(utils.JfPackageManagerEnvVariable))
			assert.Equal(t, string(utils.Java), os.Getenv(utils.JfLanguageEnvVariable))
			assert.Equal(t, "msi", os.Getenv(utils.JfMsiEnvVariable))
		}},
		{name: "Multiple technologies", args: args{msi: "msi", technologies: []coreutils.Technology{coreutils.Maven, coreutils.Npm}}, want: func() {
			assert.Equal(t, "", os.Getenv(utils.JfPackageManagerEnvVariable))
			assert.Equal(t, "", os.Getenv(utils.JfLanguageEnvVariable))
			assert.Equal(t, "msi", os.Getenv(utils.JfMsiEnvVariable))
		}},
		{name: "Zero technologies", args: args{msi: "msi", technologies: []coreutils.Technology{}}, want: func() {
			assert.Equal(t, "", os.Getenv(utils.JfPackageManagerEnvVariable))
			assert.Equal(t, "", os.Getenv(utils.JfLanguageEnvVariable))
			assert.Equal(t, "msi", os.Getenv(utils.JfMsiEnvVariable))
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			callback := SetAnalyticsMetricsDataForAnalyzerManager(tt.args.msi, tt.args.technologies)
			tt.want()
			callback()
			assert.Equal(t, "", os.Getenv(utils.JfPackageManagerEnvVariable))
			assert.Equal(t, "", os.Getenv(utils.JfLanguageEnvVariable))
			assert.Equal(t, "", os.Getenv(utils.JfMsiEnvVariable))

		})
	}
}
