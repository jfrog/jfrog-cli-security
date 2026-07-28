package packageupdaters

import (
	"fmt"

	"github.com/jfrog/jfrog-cli-security/utils/formats"
	"github.com/jfrog/jfrog-cli-security/utils/techutils"
)

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

type UnsupportedErrorType string

const (
	IndirectDependencyFixNotSupported UnsupportedErrorType = "IndirectDependencyFixNotSupported"
)

type ErrUnsupportedFix struct {
	PackageName  string
	FixedVersion string
	ErrorType    UnsupportedErrorType
}

func (err *ErrUnsupportedFix) Error() string {
	if err.ErrorType == IndirectDependencyFixNotSupported {
		return fmt.Sprintf("skipping fix of vulnerable package '%s' version '%s' - indirect dependency fix is not supported", err.PackageName, err.FixedVersion)
	}
	return fmt.Sprintf("skipping fix of vulnerable package '%s' version '%s' - build tools dependency fix is not supported", err.PackageName, err.FixedVersion)
}

type PackageUpdater interface {
	UpdateDependency(details *FixDetails) error
}
