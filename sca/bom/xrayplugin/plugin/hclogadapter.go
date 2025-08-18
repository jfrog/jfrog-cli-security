package plugin

import (
	"fmt"
	"io"
	"log"

	"github.com/hashicorp/go-hclog"
	jfrogLog "github.com/jfrog/jfrog-client-go/utils/log"
)

// HclogToJfrogAdapter adapts hclog.Logger interface to use JFrog's logger
type HclogToJfrogAdapter struct {
	logger jfrogLog.Log
}

// NewHclogToJfrogAdapter creates a new adapter that implements hclog.Logger using JFrog's logger
func NewHclogToJfrogAdapter() hclog.Logger {
	return &HclogToJfrogAdapter{
		logger: jfrogLog.GetLogger(),
	}
}

// Log implements hclog.Logger.Log
func (a *HclogToJfrogAdapter) Log(level hclog.Level, msg string, args ...interface{}) {
	switch level {
	case hclog.Error:
		a.Error(msg, args...)
	case hclog.Warn:
		a.Warn(msg, args...)
	case hclog.Info:
		a.Info(msg, args...)
	case hclog.Debug:
		a.Debug(msg, args...)
	case hclog.Trace:
		a.Trace(msg, args...)
	default:
		a.Debug(msg, args...)
	}
}

// Trace implements hclog.Logger.Trace
func (a *HclogToJfrogAdapter) Trace(msg string, args ...interface{}) {
	toLog := msg
	if len(args) > 0 {
		toLog = fmt.Sprintf(msg, args...)
	}
	a.logger.Debug(toLog)
}

// Debug implements hclog.Logger.Debug
func (a *HclogToJfrogAdapter) Debug(msg string, args ...interface{}) {
	toLog := msg
	if len(args) > 0 {
		toLog = fmt.Sprintf(msg, args...)
	}
	a.logger.Debug(toLog)
}

// Info implements hclog.Logger.Info
func (a *HclogToJfrogAdapter) Info(msg string, args ...interface{}) {
	toLog := msg
	if len(args) > 0 {
		toLog = fmt.Sprintf(msg, args...)
	}
	a.logger.Info(toLog)
}

// Warn implements hclog.Logger.Warn
func (a *HclogToJfrogAdapter) Warn(msg string, args ...interface{}) {
	toLog := msg
	if len(args) > 0 {
		toLog = fmt.Sprintf(msg, args...)
	}
	a.logger.Warn(toLog)
}

// Error implements hclog.Logger.Error
func (a *HclogToJfrogAdapter) Error(msg string, args ...interface{}) {
	toLog := msg
	if len(args) > 0 {
		toLog = fmt.Sprintf(msg, args...)
	}
	a.logger.Error(toLog)
}

// IsTrace implements hclog.Logger.IsTrace
func (a *HclogToJfrogAdapter) IsTrace() bool {
	return a.logger.GetLogLevel() >= jfrogLog.DEBUG
}

// IsDebug implements hclog.Logger.IsDebug
func (a *HclogToJfrogAdapter) IsDebug() bool {
	return a.logger.GetLogLevel() >= jfrogLog.DEBUG
}

// IsInfo implements hclog.Logger.IsInfo
func (a *HclogToJfrogAdapter) IsInfo() bool {
	return a.logger.GetLogLevel() >= jfrogLog.INFO
}

// IsWarn implements hclog.Logger.IsWarn
func (a *HclogToJfrogAdapter) IsWarn() bool {
	return a.logger.GetLogLevel() >= jfrogLog.WARN
}

// IsError implements hclog.Logger.IsError
func (a *HclogToJfrogAdapter) IsError() bool {
	return a.logger.GetLogLevel() >= jfrogLog.ERROR
}

// ImpliedArgs implements hclog.Logger.ImpliedArgs
func (a *HclogToJfrogAdapter) ImpliedArgs() []interface{} {
	return nil
}

// With implements hclog.Logger.With
func (a *HclogToJfrogAdapter) With(args ...interface{}) hclog.Logger {
	// For simplicity, return the same logger since JFrog logger doesn't support context
	return a
}

// Name implements hclog.Logger.Name
func (a *HclogToJfrogAdapter) Name() string {
	return "jfrog-adapter"
}

// Named implements hclog.Logger.Named
func (a *HclogToJfrogAdapter) Named(name string) hclog.Logger {
	// For simplicity, return the same logger since JFrog logger doesn't support named loggers
	return a
}

// ResetNamed implements hclog.Logger.ResetNamed
func (a *HclogToJfrogAdapter) ResetNamed(name string) hclog.Logger {
	// For simplicity, return the same logger
	return a
}

// SetLevel implements hclog.Logger.SetLevel
func (a *HclogToJfrogAdapter) SetLevel(level hclog.Level) {
	// Note: JFrog logger interface doesn't provide a SetLogLevel method
	// This is a limitation of the current JFrog logger interface
	// The level conversion is done in GetLevel() method instead
	if jfrogLogger, ok := a.logger.(jfrogLog.JfrogLogger); ok {
		switch level {
		case hclog.Error:
			jfrogLogger.SetLogLevel(jfrogLog.ERROR)
		case hclog.Warn:
			jfrogLogger.SetLogLevel(jfrogLog.WARN)
		case hclog.Info:
			jfrogLogger.SetLogLevel(jfrogLog.INFO)
		case hclog.Debug:
			jfrogLogger.SetLogLevel(jfrogLog.DEBUG)
		default:
			jfrogLogger.SetLogLevel(jfrogLog.DEBUG)
		}
	}
}

// GetLevel implements hclog.Logger.GetLevel
func (a *HclogToJfrogAdapter) GetLevel() hclog.Level {
	jfrogLevel := a.logger.GetLogLevel()
	switch jfrogLevel {
	case jfrogLog.ERROR:
		return hclog.Error
	case jfrogLog.WARN:
		return hclog.Warn
	case jfrogLog.INFO:
		return hclog.Info
	case jfrogLog.DEBUG:
		return hclog.Debug
	default:
		return hclog.Debug
	}
}

// StandardLogger implements hclog.Logger.StandardLogger
func (a *HclogToJfrogAdapter) StandardLogger(opts *hclog.StandardLoggerOptions) *log.Logger {
	// Return a standard logger that writes to a custom writer that forwards to JFrog logger
	return log.New(&jfrogLogWriter{adapter: a}, "", 0)
}

// StandardWriter implements hclog.Logger.StandardWriter
func (a *HclogToJfrogAdapter) StandardWriter(opts *hclog.StandardLoggerOptions) io.Writer {
	return &jfrogLogWriter{adapter: a}
}

// jfrogLogWriter is a writer that forwards writes to the JFrog logger
type jfrogLogWriter struct {
	adapter *HclogToJfrogAdapter
}

func (w *jfrogLogWriter) Write(p []byte) (n int, err error) {
	// Trim whitespace and skip empty messages
	w.adapter.logger.Output(string(p))
	return len(p), nil
}
