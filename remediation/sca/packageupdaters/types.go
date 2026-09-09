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
	// NoInlineVersionFixNotSupported covers a PackageReference with no inline version, no
	// VersionOverride, and no resolvable entry in the nearest Directory.Packages.props (or no such
	// file at all) - it may still be supplied via Directory.Build.props, a farther/unrelated
	// centrally-managed file, or be an SDK-implicit reference.
	NoInlineVersionFixNotSupported UnsupportedErrorType = "NoInlineVersionFixNotSupported"
	UnsupportedFixReason           UnsupportedErrorType = "UnsupportedFixReason"
)

type ErrUnsupportedFix struct {
	PackageName  string
	FixedVersion string
	ErrorType    UnsupportedErrorType
	Reason       string
}

func (err *ErrUnsupportedFix) Error() string {
	switch err.ErrorType {
	case IndirectDependencyFixNotSupported:
		return fmt.Sprintf("skipping fix of vulnerable package '%s' version '%s' - indirect dependency fix is not supported", err.PackageName, err.FixedVersion)
	case NoInlineVersionFixNotSupported:
		return fmt.Sprintf("skipping fix of vulnerable package '%s' version '%s' - could not resolve a version to fix (no inline attribute, VersionOverride, or matching Directory.Packages.props entry found)", err.PackageName, err.FixedVersion)
	case UnsupportedFixReason:
		return fmt.Sprintf("skipping fix of vulnerable package '%s' version '%s' - %s", err.PackageName, err.FixedVersion, err.Reason)
	default:
		return fmt.Sprintf("skipping fix of vulnerable package '%s' version '%s' - build tools dependency fix is not supported", err.PackageName, err.FixedVersion)
	}
}

type PackageUpdater interface {
	UpdateDependency(details *FixDetails) error
}
