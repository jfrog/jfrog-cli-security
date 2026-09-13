package formats

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEscapeMarkdownTableCell(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{"verify when the text is ordinary then it is untouched", "actions/checkout", "actions/checkout"},
		{"verify when the value is empty then it stays empty", "", ""},
		{"verify when the value contains a pipe then the pipe is escaped", "refs|heads", `refs\|heads`},
		{"verify when the value contains several pipes then every one is escaped", "a|b|c", `a\|b\|c`},
		{"verify when the value contains a backslash then it is escaped first", `a\b`, `a\\b`},
		{"verify when the value contains an already-escaped pipe then both characters stay literal", `a\|b`, `a\\\|b`},
		{"verify when the value contains a newline then it becomes a line break", "first\nsecond", "first<br>second"},
		{"verify when the value contains a carriage return newline then it becomes one line break", "first\r\nsecond", "first<br>second"},
		{"verify when the value contains a bare carriage return then it becomes a line break", "first\rsecond", "first<br>second"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, EscapeMarkdownTableCell(tt.value))
		})
	}
}
