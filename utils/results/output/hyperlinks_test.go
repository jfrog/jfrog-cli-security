package output

import (
	"testing"

	"github.com/jfrog/jfrog-client-go/utils/log"
	"github.com/stretchr/testify/assert"
)

func TestTerminalSupportsHyperlinks(t *testing.T) {
	t.Run("not a terminal, regardless of TERM_PROGRAM", func(t *testing.T) {
		defer log.SetIsTerminalFlagsWithCallback(false)()
		t.Setenv("TERM_PROGRAM", "iTerm.app")
		assert.False(t, TerminalSupportsHyperlinks())
	})

	t.Run("a terminal", func(t *testing.T) {
		defer log.SetIsTerminalFlagsWithCallback(true)()

		t.Setenv("TERM_PROGRAM", "")
		t.Setenv("WT_SESSION", "")
		t.Setenv("KITTY_WINDOW_ID", "")
		assert.False(t, TerminalSupportsHyperlinks())

		t.Setenv("TERM_PROGRAM", "iTerm.app")
		assert.True(t, TerminalSupportsHyperlinks())

		t.Setenv("TERM_PROGRAM", "Terminal.app")
		assert.False(t, TerminalSupportsHyperlinks())

		t.Setenv("WT_SESSION", "session")
		assert.True(t, TerminalSupportsHyperlinks())
	})
}
