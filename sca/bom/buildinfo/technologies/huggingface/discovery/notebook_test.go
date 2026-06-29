package discovery

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseNotebook_CodeCell(t *testing.T) {
	nb := `{
  "cells": [
    {
      "cell_type": "markdown",
      "source": ["# Heading"]
    },
    {
      "cell_type": "code",
      "source": ["from transformers import AutoModel\n", "model = AutoModel.from_pretrained(\"org/model\", revision=\"v1\")\n"]
    }
  ]
}`
	disc, unres, err := parseNotebookBytes([]byte(nb), "test.ipynb")
	require.NoError(t, err)
	require.Len(t, disc, 1)
	assert.Equal(t, "org/model", disc[0].RepoID)
	assert.Equal(t, "v1", disc[0].Revision)
	assert.Contains(t, disc[0].Sources[0].File, "test.ipynb#cell-")
	assert.Empty(t, unres)
}

func TestParseNotebook_MagicsStripped(t *testing.T) {
	nb := `{
  "cells": [
    {
      "cell_type": "code",
      "source": ["!pip install transformers\n", "%load_ext autoreload\n", "from_pretrained(\"org/model\")\n"]
    }
  ]
}`
	disc, _, err := parseNotebookBytes([]byte(nb), "nb.ipynb")
	require.NoError(t, err)
	require.Len(t, disc, 1)
	assert.Equal(t, "org/model", disc[0].RepoID)
}

func TestParseNotebook_MarkdownCellSkipped(t *testing.T) {
	nb := `{
  "cells": [
    {
      "cell_type": "markdown",
      "source": ["snapshot_download(repo_id=\"org/should-not-match\")"]
    }
  ]
}`
	disc, _, err := parseNotebookBytes([]byte(nb), "nb.ipynb")
	require.NoError(t, err)
	assert.Empty(t, disc)
}

func TestParseNotebook_InvalidJSON(t *testing.T) {
	_, _, err := parseNotebookBytes([]byte("not json"), "bad.ipynb")
	require.Error(t, err)
}

func TestStripMagics(t *testing.T) {
	src := "!pip install foo\n%load_ext bar\nimport torch\n"
	out := stripMagics(src)
	lines := splitLines(out)
	assert.Equal(t, "", lines[0])
	assert.Equal(t, "", lines[1])
	assert.Equal(t, "import torch", lines[2])
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}
