package sshclient

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestRingBufferCursorAndTruncation(t *testing.T) {
	buffer := NewRingBuffer(1024)
	buffer.Append([]byte(strings.Repeat("a", 1100)))
	data, cursor, open, truncated, _ := buffer.Read(context.Background(), 0, 100, 0)
	if len(data) != 100 || cursor != 176 || !open || !truncated {
		t.Fatalf("环形缓冲区结果异常: len=%d cursor=%d open=%v truncated=%v", len(data), cursor, open, truncated)
	}
}

func TestRingBufferWaitAndClose(t *testing.T) {
	buffer := NewRingBuffer(1024)
	go func() {
		time.Sleep(10 * time.Millisecond)
		buffer.Append([]byte("ok"))
		buffer.Close("")
	}()
	data, cursor, _, _, _ := buffer.Read(context.Background(), 0, 10, time.Second)
	if string(data) != "ok" || cursor != 2 {
		t.Fatalf("等待读取结果异常: %q, %d", data, cursor)
	}
	_, _, open, _, _ := buffer.Read(context.Background(), cursor, 10, time.Second)
	if open {
		t.Fatal("缓冲区关闭后仍报告为打开状态")
	}
}

func TestLimitedWriter(t *testing.T) {
	writer := NewLimitedWriter(4)
	count, err := writer.Write([]byte("abcdef"))
	if err != nil || count != 6 || writer.String() != "abcd" || !writer.Truncated() {
		t.Fatalf("限额写入结果异常: count=%d value=%q truncated=%v err=%v", count, writer.String(), writer.Truncated(), err)
	}
}
