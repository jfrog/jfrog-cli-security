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
	IndirectDependencyFixNotSupported       UnsupportedErrorType = "IndirectDependencyFixNotSupported"
	CentralPackageManagementFixNotSupported UnsupportedErrorType = "CentralPackageManagementFixNotSupported"
)

type ErrUnsupportedFix struct {
	PackageName  string
	FixedVersion string
	ErrorType    UnsupportedErrorType
}

func (err *ErrUnsupportedFix) Error() string {
	switch err.ErrorType {
	case IndirectDependencyFixNotSupported:
		return fmt.Sprintf("skipping fix of vulnerable package '%s' version '%s' - indirect dependency fix is not supported", err.PackageName, err.FixedVersion)
	case CentralPackageManagementFixNotSupported:
		return fmt.Sprintf("skipping fix of vulnerable package '%s' version '%s' - package version is centrally managed (NuGet Central Package Management) and fixing it is not yet supported", err.PackageName, err.FixedVersion)
	default:
		return fmt.Sprintf("skipping fix of vulnerable package '%s' version '%s' - build tools dependency fix is not supported", err.PackageName, err.FixedVersion)
	}
}

type PackageUpdater interface {
	UpdateDependency(details *FixDetails) error
}
