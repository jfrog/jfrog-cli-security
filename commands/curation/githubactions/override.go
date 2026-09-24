package githubactions

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/jfrog/gofrog/unarchive"
)

const (
	// overrideTempPattern names the working directory made beside an action while its content is
	// replaced. The leading dot keeps it out of casual listings; it is removed before returning.
	overrideTempPattern = ".jfrog-curation-*"
	// overrideArchiveName must end in the archive's extension: the unarchiver picks the format
	// from the name, not from the bytes.
	overrideArchiveName = "action.tar.gz"
)

// rename is os.Rename, swappable so a test can fail the swap partway.
var rename = os.Rename

// ReplaceActionContent replaces the contents of actionDir - one action's directory in the
// runner's cache - with the tar.gz archive read from archive, stripping the archive's single
// top-level directory.
//
// actionDir must be the directory the runner itself created, ActionRef.Path: the runner names it
// after the literal ref in the uses: line, so @refs/tags/v4 lives at .../refs/tags/v4, not .../v4.
//
// The swap is atomic from the runner's view: the archive is extracted into a sibling directory
// first and moved into place with renames, so actionDir holds either the old content or the new,
// never a half-extracted mix, and a failure before the swap leaves it untouched. The runner's
// "<ref>.completed" marker is a sibling of actionDir, not inside it, so it is kept.
//
// When the runner made actionDir a symlink into its shared archive cache, the link itself is
// replaced by a directory; the shared copy it pointed at is not modified.
func ReplaceActionContent(actionDir string, archive io.Reader) (err error) {
	if _, err = os.Lstat(actionDir); err != nil {
		return fmt.Errorf("replacing action content at %q: %w", actionDir, err)
	}
	// Beside actionDir rather than in os.TempDir: a rename only works within one filesystem.
	workDir, err := os.MkdirTemp(filepath.Dir(actionDir), overrideTempPattern)
	if err != nil {
		return fmt.Errorf("creating a working directory to replace action content at %q: %w", actionDir, err)
	}
	defer func() {
		if cleanupErr := os.RemoveAll(workDir); cleanupErr != nil {
			err = errors.Join(err, fmt.Errorf("removing working directory %q: %w", workDir, cleanupErr))
		}
	}()

	extracted, err := extractArchive(archive, workDir)
	if err != nil {
		return fmt.Errorf("extracting the action archive for %q: %w", actionDir, err)
	}
	return swapDirectory(actionDir, extracted, filepath.Join(workDir, "previous"))
}

// extractArchive writes archive into workDir and unpacks it, returning the directory holding the
// content with the archive's top-level directory stripped.
func extractArchive(archive io.Reader, workDir string) (string, error) {
	archivePath := filepath.Join(workDir, overrideArchiveName)
	if err := writeArchive(archivePath, archive); err != nil {
		return "", err
	}
	extracted := filepath.Join(workDir, "extracted")
	if err := os.Mkdir(extracted, 0o755); err != nil {
		return "", err
	}
	// Inspection is left on: it refuses entries and symlinks that would land outside extracted.
	unarchiver := &unarchive.Unarchiver{StripComponents: 1}
	if err := unarchiver.Unarchive(archivePath, overrideArchiveName, extracted); err != nil {
		return "", err
	}
	entries, err := os.ReadDir(extracted)
	if err != nil {
		return "", err
	}
	if len(entries) == 0 {
		// Replacing an action with nothing would leave the runner an empty directory to execute.
		return "", errors.New("the archive holds no content")
	}
	return extracted, nil
}

// writeArchive streams archive to path; a download is an archive, so it is never held in memory.
func writeArchive(path string, archive io.Reader) (err error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()
	if _, err = io.Copy(file, archive); err != nil {
		return fmt.Errorf("writing the action archive: %w", err)
	}
	return nil
}

// swapDirectory moves replacement into target's place, parking the old content at previous.
// If the second rename fails the first is undone, so target is never left missing.
func swapDirectory(target, replacement, previous string) error {
	if err := rename(target, previous); err != nil {
		return fmt.Errorf("moving the current action content at %q aside: %w", target, err)
	}
	if err := rename(replacement, target); err != nil {
		if restoreErr := rename(previous, target); restoreErr != nil {
			return errors.Join(
				fmt.Errorf("moving the new action content into %q: %w", target, err),
				fmt.Errorf("restoring the original action content at %q: %w", target, restoreErr),
			)
		}
		return fmt.Errorf("moving the new action content into %q, original restored: %w", target, err)
	}
	return nil
}
