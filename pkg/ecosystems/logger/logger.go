package logger

import (
	"context"
	"log/slog"

	"github.com/rs/zerolog"
)

// Field represents a key-value pair for structured logging.
type Field struct {
	Key   string
	Value any
}

// Attr creates a Field with the given key and value.
func Attr(key string, value any) Field {
	return Field{Key: key, Value: value}
}

// Err creates a Field for an error with the standard "error" key.
func Err(err error) Field {
	var errMsg string
	if err != nil {
		errMsg = err.Error()
	}
	return Field{Key: "err_msg", Value: errMsg}
}

// Logger is an interface for logging that supports Info, Debug, and Error operations.
type Logger interface {
	Info(ctx context.Context, msg string, fields ...Field)
	Debug(ctx context.Context, msg string, fields ...Field)
	Error(ctx context.Context, msg string, fields ...Field)
}

// NewFromZerolog wraps a zerolog.Logger to satisfy the Logger interface.
func NewFromZerolog(zl *zerolog.Logger) Logger {
	return &zerologAdapter{zl: zl}
}

type zerologAdapter struct {
	zl *zerolog.Logger
}

func (z *zerologAdapter) Info(ctx context.Context, msg string, fields ...Field) {
	e := z.zl.Info().Ctx(ctx)
	for _, f := range fields {
		e = e.Any(f.Key, f.Value)
	}
	e.Msg(msg)
}

func (z *zerologAdapter) Debug(ctx context.Context, msg string, fields ...Field) {
	e := z.zl.Debug().Ctx(ctx)
	for _, f := range fields {
		e = e.Any(f.Key, f.Value)
	}
	e.Msg(msg)
}

func (z *zerologAdapter) Error(ctx context.Context, msg string, fields ...Field) {
	e := z.zl.Error().Ctx(ctx)
	for _, f := range fields {
		e = e.Any(f.Key, f.Value)
	}
	e.Msg(msg)
}

// NewFromSlog wraps a slog.Logger to satisfy the Logger interface.
func NewFromSlog(sl *slog.Logger) Logger {
	return &slogAdapter{sl: sl}
}

type slogAdapter struct {
	sl *slog.Logger
}

func (s *slogAdapter) Info(ctx context.Context, msg string, fields ...Field) {
	s.sl.InfoContext(ctx, msg, fieldsToSlogAttrs(fields)...)
}

func (s *slogAdapter) Debug(ctx context.Context, msg string, fields ...Field) {
	s.sl.DebugContext(ctx, msg, fieldsToSlogAttrs(fields)...)
}

func (s *slogAdapter) Error(ctx context.Context, msg string, fields ...Field) {
	s.sl.ErrorContext(ctx, msg, fieldsToSlogAttrs(fields)...)
}

func fieldsToSlogAttrs(fields []Field) []any {
	attrs := make([]any, len(fields))
	for i, f := range fields {
		attrs[i] = slog.Any(f.Key, f.Value)
	}
	return attrs
}

// Nop returns a no-op logger that discards all output.
func Nop() Logger {
	return &nopLogger{}
}

type nopLogger struct{}

func (n *nopLogger) Info(_ context.Context, _ string, _ ...Field)  {}
func (n *nopLogger) Debug(_ context.Context, _ string, _ ...Field) {}
func (n *nopLogger) Error(_ context.Context, _ string, _ ...Field) {}
