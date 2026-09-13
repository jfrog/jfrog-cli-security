package formats

import "strings"

// The backslash rule comes first so an input already containing "\|" keeps both characters
// literal instead of yielding an unescaped separator.
var markdownTableCellEscaper = strings.NewReplacer(
	`\`, `\\`,
	`|`, `\|`,
	"\r\n", "<br>",
	"\n", "<br>",
	"\r", "<br>",
)

// EscapeMarkdownTableCell renders value safely inside one GitHub-flavored markdown table cell:
// "|" would open a new cell and a newline would end the row.
func EscapeMarkdownTableCell(value string) string {
	return markdownTableCellEscaper.Replace(value)
}
