package sshclient

import "bytes"

type LimitedWriter struct {
	buffer    bytes.Buffer
	limit     int
	truncated bool
}

func NewLimitedWriter(limit int) *LimitedWriter {
	if limit <= 0 {
		limit = 1024 * 1024
	}
	return &LimitedWriter{limit: limit}
}

func (w *LimitedWriter) Write(value []byte) (int, error) {
	original := len(value)
	remaining := w.limit - w.buffer.Len()
	if remaining <= 0 {
		w.truncated = true
		return original, nil
	}
	if len(value) > remaining {
		value = value[:remaining]
		w.truncated = true
	}
	_, _ = w.buffer.Write(value)
	return original, nil
}

func (w *LimitedWriter) String() string  { return w.buffer.String() }
func (w *LimitedWriter) Truncated() bool { return w.truncated }
