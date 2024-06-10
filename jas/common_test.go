package jas

import (
	"os"
	"testing"

	"github.com/jfrog/jfrog-cli-security/formats/sarifutils"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
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
				sarifutils.CreateResultWithOneLocation("", 0, 0, 0, 0, "snippet1", "ruleId1", "level1"),
				sarifutils.CreateResultWithOneLocation("", 0, 0, 0, 0, "snippet2", "ruleId2", "level2"),
			},
			expectedOutput: []*sarif.Result{
				sarifutils.CreateResultWithOneLocation("", 0, 0, 0, 0, "snippet1", "ruleId1", "level1"),
				sarifutils.CreateResultWithOneLocation("", 0, 0, 0, 0, "snippet2", "ruleId2", "level2"),
			},
		},
		{
			sarifResults: []*sarif.Result{
				sarifutils.CreateResultWithOneLocation("", 0, 0, 0, 0, "snippet1", "ruleId1", "level1").WithSuppression([]*sarif.Suppression{sarif.NewSuppression("")}),
				sarifutils.CreateResultWithOneLocation("", 0, 0, 0, 0, "snippet2", "ruleId2", "level2"),
			},
			expectedOutput: []*sarif.Result{
				sarifutils.CreateResultWithOneLocation("", 0, 0, 0, 0, "snippet2", "ruleId2", "level2"),
			},
		},
		{
			sarifResults: []*sarif.Result{
				sarifutils.CreateResultWithOneLocation("", 0, 0, 0, 0, "snippet1", "ruleId1", "level1").WithSuppression([]*sarif.Suppression{sarif.NewSuppression("")}),
				sarifutils.CreateResultWithOneLocation("", 0, 0, 0, 0, "snippet2", "ruleId2", "level2").WithSuppression([]*sarif.Suppression{sarif.NewSuppression("")}),
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
			sarifRun: sarifutils.CreateRunWithDummyResults(
				sarifutils.CreateResultWithOneLocation("file1", 0, 0, 0, 0, "snippet", "rule1", "info"),
				sarifutils.CreateResultWithOneLocation("file2", 0, 0, 0, 0, "snippet", "rule1", "info"),
				sarifutils.CreateResultWithOneLocation("file", 0, 0, 0, 0, "snippet", "rule2", "warning"),
			),
			expectedOutput: []*sarif.ReportingDescriptor{
				sarif.NewRule("rule1").WithProperties(sarif.Properties{"security-severity": "6.9"}),
				sarif.NewRule("rule2").WithProperties(sarif.Properties{"security-severity": "6.9"}),
			},
		},
		{
			sarifRun: sarifutils.CreateRunWithDummyResults(
				sarifutils.CreateResultWithOneLocation("file", 0, 0, 0, 0, "snippet", "rule1", "none"),
				sarifutils.CreateResultWithOneLocation("file", 0, 0, 0, 0, "snippet", "rule2", "note"),
				sarifutils.CreateResultWithOneLocation("file", 0, 0, 0, 0, "snippet", "rule3", "info"),
				sarifutils.CreateResultWithOneLocation("file", 0, 0, 0, 0, "snippet", "rule4", "warning"),
				sarifutils.CreateResultWithOneLocation("file", 0, 0, 0, 0, "snippet", "rule5", "error"),
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
		technologies []techutils.Technology
	}
	tests := []struct {
		name string
		args args
		want func()
	}{
		{name: "One valid technology", args: args{msi: "msi", technologies: []techutils.Technology{techutils.Maven}}, want: func() {
			assert.Equal(t, string(techutils.Maven), os.Getenv(JfPackageManagerEnvVariable))
			assert.Equal(t, string(techutils.Java), os.Getenv(JfLanguageEnvVariable))
			assert.Equal(t, "msi", os.Getenv(JfMsiEnvVariable))
		}},
		{name: "Multiple technologies", args: args{msi: "msi", technologies: []techutils.Technology{techutils.Maven, techutils.Npm}}, want: func() {
			assert.Equal(t, "", os.Getenv(JfPackageManagerEnvVariable))
			assert.Equal(t, "", os.Getenv(JfLanguageEnvVariable))
			assert.Equal(t, "msi", os.Getenv(JfMsiEnvVariable))
		}},
		{name: "Zero technologies", args: args{msi: "msi", technologies: []techutils.Technology{}}, want: func() {
			assert.Equal(t, "", os.Getenv(JfPackageManagerEnvVariable))
			assert.Equal(t, "", os.Getenv(JfLanguageEnvVariable))
			assert.Equal(t, "msi", os.Getenv(JfMsiEnvVariable))
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			callback := SetAnalyticsMetricsDataForAnalyzerManager(tt.args.msi, tt.args.technologies)
			tt.want()
			callback()
			assert.Equal(t, "", os.Getenv(JfPackageManagerEnvVariable))
			assert.Equal(t, "", os.Getenv(JfLanguageEnvVariable))
			assert.Equal(t, "", os.Getenv(JfMsiEnvVariable))

		})
	}
}
