package audit

import (
	"github.com/jfrog/jfrog-client-go/utils/log"
)

// LogCollector captures logs for isolated parallel audit operations.
type LogCollector struct {
	logger *log.BufferedLogger
}

func NewLogCollector(level log.LevelType) *LogCollector {
	return &LogCollector{
		logger: log.NewBufferedLogger(level),
	}
}

func (c *LogCollector) Logger() log.Log {
	return c.logger
}

// ReplayTo outputs captured logs through the target logger (preserving colors).
func (c *LogCollector) ReplayTo(target log.Log) {
	c.logger.ReplayTo(target)
}

func (c *LogCollector) HasLogs() bool {
	return c.logger.Len() > 0
}

func (c *LogCollector) Len() int {
	return c.logger.Len()
}

func (c *LogCollector) String() string {
	return c.logger.String()
}

func (c *LogCollector) Clear() {
	c.logger.Clear()
}
