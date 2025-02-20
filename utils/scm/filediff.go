package scm

import (
	"fmt"
	// "strings"

	goDiff "github.com/go-git/go-git/v5/plumbing/format/diff"

	"github.com/jfrog/gofrog/datastructures"
	"github.com/jfrog/jfrog-client-go/utils/log"
)

type ChangesRelevantToScan struct {
	ChangedFiles    []FileChanges
	ChangedBinaries []string
}

func (c ChangesRelevantToScan) HasChanges() bool {
	return c.HasFileChanges() || c.HasBinaryChanges()
}

func (c ChangesRelevantToScan) HasFileChanges() bool {
	return len(c.ChangedFiles) > 0
}

func (c ChangesRelevantToScan) HasBinaryChanges() bool {
	return len(c.ChangedBinaries) > 0
}

func (c ChangesRelevantToScan) GetChangedFilesPaths() (paths []string) {
	for _, file := range c.ChangedFiles {
		paths = append(paths, file.Path)
	}
	return
}

func (c ChangesRelevantToScan) GetFileChanges(path string) (changes *FileChanges) {
	for _, file := range c.ChangedFiles {
		if file.Path == path {
			return &file
		}
	}
	return
}

// FileChangeRanges represents the changes in the
type FileChanges struct {
	Path    string
	Changes []Range
}

func (f FileChanges) String() string {
	return fmt.Sprintf("%s: %v", f.Path, f.Changes)
}

func (f FileChanges) Contains(startRow, startCol, endRow, endCol int) bool {
	for _, change := range f.Changes {
		if change.Contains(startRow, startCol, endRow, endCol) {
			return true
		}
	}
	return false
}

func (f FileChanges) Overlaps(startRow, startCol, endRow, endCol int) bool {
	for _, change := range f.Changes {
		if change.Overlaps(startRow, startCol, endRow, endCol) {
			return true
		}
	}
	return false
}

type Range struct {
	StartRow int
	StartCol int
	EndRow   int
	EndCol   int
}

func (r Range) String() string {
	return fmt.Sprintf("%d:%d-%d:%d", r.StartRow, r.StartCol, r.EndRow, r.EndCol)
}

// Contains checks if the range contains (fully) the given range
func (r Range) Contains(startRow, startCol, endRow, endCol int) bool {
	return r.StartRow <= startRow && r.StartCol <= startCol && r.EndRow >= endRow && r.EndCol >= endCol
}

// Overlaps checks if the range overlaps (partially or fully) the given range
func (r Range) Overlaps(startRow, startCol, endRow, endCol int) bool {
	return r.StartRow < endRow && r.EndRow > startRow && r.StartCol < endCol && r.EndCol > startCol
}

func detectRelevantChanges(filePatches []goDiff.FilePatch) (changes ChangesRelevantToScan, err error) {
	binariesChanged := datastructures.MakeSet[string]()
	// Go over the file patches and detect the relevant changes
	for _, filePatch := range filePatches {
		from, to := filePatch.Files()
		fromPath := ""
		if from != nil {
			fromPath = from.Path()
		}
		toPath := ""
		if to != nil {
			toPath = to.Path()
		}
		log.Debug(fmt.Sprintf("Checking Diff between: %s (from) and %s (to)", fromPath, toPath))
		// Get the relevant changes for the file
		if filePatch.IsBinary() {
			// Binary file, only file path is relevant
			binariesChanged.Add(to.Path())
			continue
		}
		if to == nil {
			// Deleted file, not relevant to scan
			continue
		}
		// Get the relevant changes in the file, if new file (from is nil) all the content is relevant
		if fileChanges := processFileChunksForRelevantChanges(filePatch.Chunks(), from == nil); /*len(fileChanges) > 0*/ true {
			changes.ChangedFiles = append(changes.ChangedFiles, FileChanges{Path: to.Path(), Changes: fileChanges})
		}
	}
	changes.ChangedBinaries = binariesChanged.ToSlice()
	return
}

func processFileChunksForRelevantChanges(fileChunks []goDiff.Chunk /*isNewFile*/, _ bool) (relevantChanges []Range) {
	// SARIF locations start at 1
	row, col := 1, 1
	for _, diffChunk := range fileChunks {
		chunkContent := diffChunk.Content()
		log.Debug(fmt.Sprintf("Chunk (type = %d): \"%s\"", diffChunk.Type(), chunkContent))
		switch diffChunk.Type() {
		case goDiff.Add:
			// Added content
			// Add the range of the added content
			relevantChanges = append(relevantChanges, Range{StartRow: row, StartCol: col, EndRow: row, EndCol: col + len(chunkContent)})
			// Move the cursor to the end of the added content

		case goDiff.Delete:
			// Deleted content
			// Move the cursor to the end of the deleted content

		case goDiff.Equal:
			// Unchanged content
			// Move the cursor to the end of the unchanged content

		}
	}
	return
}

// func createRangeAtChunk(cursorRow, cursorCol int, chunk string) Range {
// 	return Range{StartRow: row, StartCol: col, EndRow: row, EndCol: col + len(chunk)}
// }

func getCursorNewPosition(cursorRow, cursorCol int, chunk string) (newRow, newCol int) {
	newRow, newCol = cursorRow, cursorCol
	for _, char := range chunk {
		if char == '\n' {
			newRow++
			newCol = 1
		} else {
			newCol++
		}
	}
	return
}
