package packageupdaters

import (
	"fmt"

	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
)

// FixDetails holds the minimal information an updater needs to fix a vulnerability.
type FixDetails struct {
	ImpactedDependencyName    string
	ImpactedDependencyVersion string
	SuggestedFixedVersion     string
	IsDirectDependency        bool
	Technology                techutils.Technology
	// Components holds the evidence of where the dependency appears (used by updaters
	// that discover descriptor paths from scan results).
	Components []formats.ComponentRow
	// IssueId is used for logging purposes only.
	IssueId string
}

// UnsupportedErrorType classifies the reason a fix is not supported.
type UnsupportedErrorType string

const (
	IndirectDependencyFixNotSupported UnsupportedErrorType = "IndirectDependencyFixNotSupported"
)

// ErrUnsupportedFix is returned when a fix cannot be applied for a known reason.
type ErrUnsupportedFix struct {
	PackageName  string
	FixedVersion string
	ErrorType    UnsupportedErrorType
}

func (err *ErrUnsupportedFix) Error() string {
	if err.ErrorType == IndirectDependencyFixNotSupported {
		return fmt.Sprintf("skipping fix of vulnerable package '%s' version '%s' - indirect dependency fix is not supported", err.PackageName, err.FixedVersion)
	}
	return fmt.Sprintf("skipping fix of vulnerable package '%s' - '%s', version '%s' - build tools dependency fix is not supported", err.PackageName, err.PackageName, err.FixedVersion)
}

// PackageUpdater is the interface that all technology-specific updaters implement.
type PackageUpdater interface {
	UpdateDependency(details *FixDetails) error
}
