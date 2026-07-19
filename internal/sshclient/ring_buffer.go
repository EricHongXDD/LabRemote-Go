package sshclient

import (
	"context"
	"time"
)

type RingBuffer struct {
	capacity int
	data     []byte
	start    uint64
	closed   bool
	errText  string
	notify   chan struct{}
	mu       chan struct{}
}

func NewRingBuffer(capacity int) *RingBuffer {
	if capacity < 1024 {
		capacity = 1024
	}
	buffer := &RingBuffer{capacity: capacity, notify: make(chan struct{}), mu: make(chan struct{}, 1)}
	buffer.mu <- struct{}{}
	return buffer
}

func (b *RingBuffer) lock()   { <-b.mu }
func (b *RingBuffer) unlock() { b.mu <- struct{}{} }

func (b *RingBuffer) Append(value []byte) {
	b.lock()
	if b.closed {
		b.unlock()
		return
	}
	b.data = append(b.data, value...)
	if len(b.data) > b.capacity {
		drop := len(b.data) - b.capacity
		copy(b.data, b.data[drop:])
		b.data = b.data[:b.capacity]
		b.start += uint64(drop)
	}
	close(b.notify)
	b.notify = make(chan struct{})
	b.unlock()
}

func (b *RingBuffer) Close(errText string) {
	b.lock()
	if !b.closed {
		b.closed = true
		b.errText = errText
		close(b.notify)
		b.notify = make(chan struct{})
	}
	b.unlock()
}

func (b *RingBuffer) Read(ctx context.Context, cursor uint64, maxBytes int, wait time.Duration) (data []byte, next uint64, open, truncated bool, errText string) {
	if maxBytes <= 0 || maxBytes > 1024*1024 {
		maxBytes = 65536
	}
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	for {
		b.lock()
		if cursor < b.start {
			cursor = b.start
			truncated = true
		}
		end := b.start + uint64(len(b.data))
		if cursor < end {
			offset := int(cursor - b.start)
			count := len(b.data) - offset
			if count > maxBytes {
				count = maxBytes
			}
			data = append([]byte(nil), b.data[offset:offset+count]...)
			next = cursor + uint64(count)
			open = !b.closed
			errText = b.errText
			b.unlock()
			return
		}
		if b.closed || wait <= 0 {
			next = cursor
			open = !b.closed
			errText = b.errText
			b.unlock()
			return
		}
		notify := b.notify
		b.unlock()
		select {
		case <-ctx.Done():
			return nil, cursor, true, truncated, ctx.Err().Error()
		case <-deadline.C:
			return nil, cursor, true, truncated, ""
		case <-notify:
		}
	}
}
