package nuget

import (
	"fmt"
	"strings"

	snykecosystems "github.com/snyk/error-catalog-golang-public/opensource/ecosystems"
)

// The NuGet diagnostic codes with a dedicated .NET entry in the error catalog.
const (
	codeCpmVersionOverride       = "NU1008"
	codeCpmMissingPackageVersion = "NU1010"
	codeCpmDisabledOrMissing     = "NU1015"
	codeIncompatibleFramework    = "NU1202"
)

// restoreFailure reports why the restore failed for targetsKey, or nil when it
// did not fail.
//
// A framework the restore failed on has no dependency set worth reporting, even
// where the packages themselves appear under it. A package incompatible with
// the framework is recorded with none of its own dependencies, so the closure
// silently loses everything below it — and a dependency missing from a graph is
// a dependency nothing downstream will look at. Whether the diagnosed package
// resolved says nothing about whether what it brings with it did.
func restoreFailure(logs []assetsLog, targetsKey string) error {
	for i := range logs {
		l := &logs[i]
		if !l.failedRestore() || !l.appliesTo(targetsKey) {
			continue
		}

		return catalogErrorForCode(l.Code, l.describe())
	}

	return nil
}

// describe renders the diagnostic for a user, naming the target frameworks when
// it applies to only some of them.
func (l *assetsLog) describe() string {
	if len(l.TargetGraphs) == 0 {
		return fmt.Sprintf("%s: %s", l.Code, l.Message)
	}

	return fmt.Sprintf("%s (%s): %s", l.Code, strings.Join(l.TargetGraphs, ", "), l.Message)
}

// catalogErrorForCode maps a NuGet diagnostic code onto the error catalog entry
// that best explains it, so a caller can tell a project the user can fix from
// one they cannot.
//
// Every failure is reported either way: a code with no dedicated entry falls
// back to the generic restore failure, which still carries the code and the
// message NuGet wrote.
func catalogErrorForCode(code, detail string) error {
	switch code {
	case codeCpmVersionOverride:
		return snykecosystems.NewCpmVersionOverrideError(detail)
	case codeCpmMissingPackageVersion:
		return snykecosystems.NewCpmMissingPackageVersionError(detail)
	case codeCpmDisabledOrMissing:
		return snykecosystems.NewCpmDisabledOrMissingVersionError(detail)
	case codeIncompatibleFramework:
		return snykecosystems.NewIncompatibleTargetFrameworkError(detail)
	default:
		return snykecosystems.NewRestoreFailedError(detail)
	}
}
