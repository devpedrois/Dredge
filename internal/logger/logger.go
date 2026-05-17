package logger

import (
	"log/slog"
	"os"
)

var buildVersion = "dev"

// New creates a structured slog.Logger.
// [SECURITY] Logs go to stderr — stdout reserved for command output (table/json)
// [SECURITY] Never log container env vars, mount paths, or secrets — sanitize before logging
func New(level, format string) *slog.Logger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: lvl}

	var handler slog.Handler
	if format == "text" {
		handler = slog.NewTextHandler(os.Stderr, opts)
	} else {
		handler = slog.NewJSONHandler(os.Stderr, opts)
	}

	return slog.New(handler).With("app", "dredge", "version", buildVersion)
}
