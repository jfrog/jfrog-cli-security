package audit

import (
	"testing"
)

// This test checks correct utilization of a Config Profile in Audit scans.
// Currently, if a config profile is provided, the scan will use the profile's settings, IGNORING jfrog-apps-config if exists.
// Currently, the only supported scanners are Secrets and Sast, therefore if a config profile is utilized - all other scanners are disabled.
func TestAuditWithConfigProfile(t *testing.T) {
	// create params

}
