package logx

import (
	"context"
	"log/slog"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Zap is a *zap.Logger for libraries that take one (certmagic and its
// ACME client). Every entry becomes a record on the default slog handler,
// so it reaches the consoles, the log file, and the ops logs API in the
// same format as ours. Call it after Setup.
func Zap() *zap.Logger {
	return zap.New(zapCore{h: slog.Default().Handler()})
}

type zapCore struct {
	h slog.Handler
}

func (c zapCore) Enabled(l zapcore.Level) bool {
	return c.h.Enabled(context.Background(), slogLevel(l))
}

func (c zapCore) With(fields []zapcore.Field) zapcore.Core {
	return zapCore{h: c.h.WithAttrs(zapAttrs(nil, fields))}
}

func (c zapCore) Check(e zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if c.Enabled(e.Level) {
		return ce.AddCore(e, c)
	}
	return ce
}

func (c zapCore) Write(e zapcore.Entry, fields []zapcore.Field) error {
	r := slog.NewRecord(e.Time, slogLevel(e.Level), e.Message, 0)
	attrs := make([]slog.Attr, 0, len(fields)+2)
	if e.LoggerName != "" {
		attrs = append(attrs, slog.String("logger", e.LoggerName))
	}
	attrs = zapAttrs(attrs, fields)
	if e.Stack != "" {
		attrs = append(attrs, slog.String("stack", e.Stack))
	}
	r.AddAttrs(attrs...)
	return c.h.Handle(context.Background(), r)
}

func (zapCore) Sync() error { return nil }

func slogLevel(l zapcore.Level) slog.Level {
	switch {
	case l <= zapcore.DebugLevel:
		return slog.LevelDebug
	case l == zapcore.InfoLevel:
		return slog.LevelInfo
	case l == zapcore.WarnLevel:
		return slog.LevelWarn
	default:
		return slog.LevelError
	}
}

// zapAttrs converts the field types certmagic and acmez use without an
// encoder; anything else goes through zap's map encoder.
func zapAttrs(out []slog.Attr, fields []zapcore.Field) []slog.Attr {
	for _, f := range fields {
		switch f.Type {
		case zapcore.StringType:
			out = append(out, slog.String(f.Key, f.String))
		case zapcore.BoolType:
			out = append(out, slog.Bool(f.Key, f.Integer == 1))
		case zapcore.Int64Type, zapcore.Int32Type, zapcore.Int16Type, zapcore.Int8Type:
			out = append(out, slog.Int64(f.Key, f.Integer))
		case zapcore.Uint64Type, zapcore.Uint32Type, zapcore.Uint16Type, zapcore.Uint8Type:
			out = append(out, slog.Uint64(f.Key, uint64(f.Integer)))
		case zapcore.DurationType:
			out = append(out, slog.Duration(f.Key, time.Duration(f.Integer)))
		case zapcore.ErrorType:
			if err, ok := f.Interface.(error); ok && err != nil {
				out = append(out, slog.String(f.Key, err.Error()))
			}
		case zapcore.SkipType:
		default:
			enc := zapcore.NewMapObjectEncoder()
			f.AddTo(enc)
			for k, v := range enc.Fields {
				out = append(out, slog.Any(k, v))
			}
		}
	}
	return out
}
