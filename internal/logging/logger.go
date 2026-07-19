package logging

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

type RedactingHandler struct {
	inner slog.Handler
}

func NewJSONLogger(path string) (*slog.Logger, io.Closer, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, nil, fmt.Errorf("创建日志目录失败: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("打开日志文件失败: %w", err)
	}
	handler := slog.NewJSONHandler(file, &slog.HandlerOptions{Level: slog.LevelInfo, ReplaceAttr: func(_ []string, attr slog.Attr) slog.Attr {
		if attr.Value.Kind() == slog.KindString {
			attr.Value = slog.StringValue(Redact(attr.Value.String()))
		}
		return attr
	}})
	return slog.New(handler), file, nil
}

func DailyPath(directory, prefix string) string {
	return filepath.Join(directory, fmt.Sprintf("%s-%s.jsonl", prefix, time.Now().Format("2006-01-02")))
}
