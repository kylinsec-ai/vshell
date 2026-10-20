// Package utils provides shared logging, configuration, authentication, and notification helpers.
package utils

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
)

// Log levels use a syslog-style scale: 0 is most severe and 7 is most verbose.
const (
	LevelEmergency     = 0 // Emergency
	LevelAlert         = 1 // Alert
	LevelCritical      = 2 // Critical
	LevelError         = 3 // Error
	LevelWarning       = 4 // Warning
	LevelNotice        = 5 // Notice
	LevelInformational = 6 // Informational
	LevelDebug         = 7 // Debug
)

var (
	loggerMu        sync.RWMutex       // Protects reads and updates to logger configuration.
	configuredLevel           = LevelDebug // Current threshold; messages at or below it are emitted.
	configuredOut   io.Writer = os.Stderr // Default destination until configuration overrides it.
)

// LoggerCloser lets callers close the configured log file during shutdown.
type LoggerCloser interface {
	io.Closer
}

// loggerCloser adapts an open file to the LoggerCloser interface.
type loggerCloser struct {
	file *os.File
}

// Close closes the underlying file; a nil receiver or file is a no-op.
func (c *loggerCloser) Close() error {
	if c == nil || c.file == nil {
		return nil
	}
	return c.file.Close()
}

// levelWriter forwards log output while reading the current destination under the configuration lock.
type levelWriter struct {
	writer io.Writer
}

// Write forwards p to the current output destination. A nil destination discards the bytes.
func (w *levelWriter) Write(p []byte) (int, error) {
	loggerMu.RLock()
	out := w.writer
	loggerMu.RUnlock()
	if out == nil {
		return len(p), nil
	}
	return out.Write(p)
}

// Sync calls the destination's Sync method when supported; other writers require no action.
func (w *levelWriter) Sync() error {
	loggerMu.RLock()
	out := w.writer
	loggerMu.RUnlock()
	if s, ok := out.(interface{ Sync() error }); ok {
		return s.Sync()
	}
	return nil
}

// ConfigureLogger applies log_level and log_path from the supplied settings.
// Levels follow a syslog-style scale (0=Emergency through 7=Debug); a message is emitted
// when its level is less than or equal to the configured threshold.
func ConfigureLogger(cfg *FullSettings) (LoggerCloser, error) {
	if cfg == nil {
		cfg = defaultFullSettings()
	}

	level := cfg.LogLevel
	if level < LevelEmergency {
		level = LevelEmergency
	}
	if level > LevelDebug {
		level = LevelDebug
	}

	var out io.Writer = os.Stderr
	var file *os.File
	if cfg.LogPath != "" {
		if dir := filepath.Dir(cfg.LogPath); dir != "." && dir != "" {
			if err := os.MkdirAll(dir, 0755); err != nil {
				return nil, fmt.Errorf("create log directory: %w", err)
			}
		}
		f, err := os.OpenFile(cfg.LogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return nil, fmt.Errorf("open log file: %w", err)
		}
		file = f
		out = f
	}

	loggerMu.Lock()
	configuredLevel = level
	configuredOut = out
	loggerMu.Unlock()

	log.SetOutput(&levelWriter{writer: out})
	log.SetFlags(log.LstdFlags)

	return &loggerCloser{file: file}, nil
}

// logAt 按级别过滤后输出日志。
// logAt emits a log message after filtering by level.
func logAt(level int, format string, args ...interface{}) {
	loggerMu.RLock()
	allowed := level <= configuredLevel
	loggerMu.RUnlock()
	if !allowed {
		return
	}
	log.Printf(format, args...)
}

// 以下为各级别的便捷输出函数 / Convenience log functions per level.
func LogEmergency(format string, args ...interface{}) { logAt(LevelEmergency, format, args...) }
func LogAlert(format string, args ...interface{})     { logAt(LevelAlert, format, args...) }
func LogCritical(format string, args ...interface{})  { logAt(LevelCritical, format, args...) }
func LogError(format string, args ...interface{})     { logAt(LevelError, format, args...) }
func LogWarning(format string, args ...interface{})   { logAt(LevelWarning, format, args...) }
func LogNotice(format string, args ...interface{})    { logAt(LevelNotice, format, args...) }
func LogInfo(format string, args ...interface{})      { logAt(LevelInformational, format, args...) }
func LogDebug(format string, args ...interface{})     { logAt(LevelDebug, format, args...) }
