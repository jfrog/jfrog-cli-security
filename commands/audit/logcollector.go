package audit

import (
	"bytes"

	"github.com/jfrog/jfrog-client-go/utils/log"
)

// LogCollector provides isolated log capture for parallel audit operations.
// Each audit can have its own LogCollector, and all logs from that audit
// will be captured in the collector's buffer without mixing with other audits.
//
// Usage:
//
//	collector := NewLogCollector(log.INFO)
//	params := NewAuditParams().SetLogCollector(collector)
//	results := RunAudit(params)
//	logs := collector.GetLogs() // Get all logs from this audit
type LogCollector struct {
	buffer *bytes.Buffer
	logger log.Log
}

// NewLogCollector creates a new log collector with the specified log level.
// All logs at or above this level will be captured.
func NewLogCollector(level log.LevelType) *LogCollector {
	buf := &bytes.Buffer{}
	return &LogCollector{
		buffer: buf,
		logger: log.NewBufferedLogger(buf, level),
	}
}

// Logger returns the isolated logger to be used for this audit.
// This logger writes to the collector's internal buffer.
func (c *LogCollector) Logger() log.Log {
	return c.logger
}

// GetLogs returns all captured logs as a string.
// Call this after the audit completes to retrieve the isolated logs.
func (c *LogCollector) GetLogs() string {
	return c.buffer.String()
}

// GetLogsAndClear returns all captured logs and clears the buffer.
// Useful if you want to retrieve logs incrementally.
func (c *LogCollector) GetLogsAndClear() string {
	logs := c.buffer.String()
	c.buffer.Reset()
	return logs
}

// Clear resets the log buffer, discarding all captured logs.
func (c *LogCollector) Clear() {
	c.buffer.Reset()
}
