package audit

import (
	"github.com/jfrog/jfrog-client-go/utils/log"
)

// LogCollector provides isolated log capture for parallel audit operations.
// Each audit can have its own LogCollector, and all logs from that audit
// will be captured without mixing with other audits.
//
// Usage:
//
//	collector := NewLogCollector(log.INFO)
//	params := NewAuditParams().SetLogCollector(collector)
//	results := RunAudit(params)
//	collector.ReplayTo(log.GetLogger()) // Replay logs with proper colors
type LogCollector struct {
	logger *log.BufferedLogger
}

// NewLogCollector creates a new log collector with the specified log level.
// All logs at or above this level will be captured.
func NewLogCollector(level log.LevelType) *LogCollector {
	return &LogCollector{
		logger: log.NewBufferedLogger(level),
	}
}

// Logger returns the isolated logger to be used for this audit.
func (c *LogCollector) Logger() log.Log {
	return c.logger
}

// ReplayTo replays all captured logs through the target logger.
// This preserves colors, formatting, and timestamps from the target logger.
func (c *LogCollector) ReplayTo(target log.Log) {
	c.logger.ReplayTo(target)
}

// HasLogs returns true if any logs have been captured.
func (c *LogCollector) HasLogs() bool {
	return c.logger.Len() > 0
}

// Len returns the number of captured log entries.
func (c *LogCollector) Len() int {
	return c.logger.Len()
}

// String returns all captured logs as a plain text string (for debugging).
// For colored output, use ReplayTo() instead.
func (c *LogCollector) String() string {
	return c.logger.String()
}

// Clear removes all captured log entries.
func (c *LogCollector) Clear() {
	c.logger.Clear()
}
