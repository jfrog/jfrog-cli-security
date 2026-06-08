package local

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/formats/violationutils"
	"github.com/jfrog/jfrog-cli-security/utils/jasutils"
	"github.com/jfrog/jfrog-cli-security/utils/results"
	"github.com/jfrog/jfrog-cli-security/utils/severityutils"
	"github.com/jfrog/jfrog-client-go/xray/services"
)

func TestForEachScanGraphViolation_emptyComponents(t *testing.T) {
	violation := services.Violation{
		IssueId:       "XRAY-iter-empty",
		Severity:      "Low",
		WatchName:     "watch",
		ViolationType: violationutils.ScaViolationTypeSecurity.String(),
		Cves:          []services.Cve{{Id: "CVE-iter-empty"}},
		Components:    map[string]services.Component{},
	}
	var securityCalls int
	_, _, err := ForEachScanGraphViolation(
		results.ScanTarget{Target: "."},
		[]string{},
		[]services.Violation{violation},
		false,
		nil,
		func(_ services.Violation, _ []formats.CveRow, _ jasutils.ApplicabilityStatus, _ severityutils.Severity, impactedPackagesId string, _ []string, _ []formats.ComponentRow, _ [][]formats.ComponentRow) error {
			securityCalls++
			assert.Empty(t, impactedPackagesId)
			return nil
		},
		nil,
		nil,
	)
	require.NoError(t, err)
	assert.Equal(t, 1, securityCalls)
}
