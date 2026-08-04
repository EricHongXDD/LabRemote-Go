package sshclient

import (
	"bytes"
	"crypto/sha256"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/pkg/sftp"
)

func TestAdaptiveUploadPipelineImprovesHighLatencyLargeFileThroughput(t *testing.T) {
	payload := bytes.Repeat([]byte("LabRemote-upload-speed\n"), 8*1024*1024/23)
	legacyDuration := measurePipelinedSFTPUpload(t, payload, 8, 8*time.Millisecond)
	optimizedDuration := measurePipelinedSFTPUpload(t, payload, uploadSFTPPipelineBudget, 8*time.Millisecond)

	t.Logf("固定 8 请求耗时 %s，自适应 64 请求耗时 %s", legacyDuration, optimizedDuration)
	if optimizedDuration*2 >= legacyDuration {
		t.Fatalf("高延迟大文件上传加速不足：固定 8 请求=%s，自适应 64 请求=%s", legacyDuration, optimizedDuration)
	}
}

func measurePipelinedSFTPUpload(t *testing.T, payload []byte, concurrency int, oneWayLatency time.Duration) time.Duration {
	t.Helper()
	remoteRoot := t.TempDir()
	clientConnection, proxyClient := net.Pipe()
	proxyServer, serverConnection := net.Pipe()
	proxy := newLatencyProxy(proxyClient, proxyServer, oneWayLatency)

	server, err := sftp.NewServer(serverConnection, sftp.WithServerWorkingDirectory(remoteRoot))
	if err != nil {
		t.Fatal(err)
	}
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Serve() }()
	client, err := sftp.NewClientPipe(
		clientConnection,
		clientConnection,
		sftp.UseConcurrentWrites(true),
		sftp.MaxConcurrentRequestsPerFile(uploadSFTPPipelineBudget),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
		proxy.Close()
		<-serverDone
	})

	remoteFile, err := client.Create("large.bin")
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	written, err := remoteFile.ReadFromWithConcurrency(bytes.NewReader(payload), concurrency)
	duration := time.Since(started)
	if closeErr := remoteFile.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatal(err)
	}
	if written != int64(len(payload)) {
		t.Fatalf("上传字节数 = %d，期望 %d", written, len(payload))
	}
	remotePayload, err := os.ReadFile(filepath.Join(remoteRoot, "large.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(remotePayload) != sha256.Sum256(payload) {
		t.Fatal("高并发上传后的远端文件内容不一致")
	}
	return duration
}

type latencyChunk struct {
	data      []byte
	deliverAt time.Time
}

type latencyProxy struct {
	left  net.Conn
	right net.Conn
	wait  sync.WaitGroup
}

func newLatencyProxy(left, right net.Conn, delay time.Duration) *latencyProxy {
	proxy := &latencyProxy{left: left, right: right}
	proxy.wait.Add(2)
	go proxy.relay(left, right, delay)
	go proxy.relay(right, left, delay)
	return proxy
}

func (proxy *latencyProxy) Close() {
	_ = proxy.left.Close()
	_ = proxy.right.Close()
	proxy.wait.Wait()
}

func (proxy *latencyProxy) relay(source, destination net.Conn, delay time.Duration) {
	defer proxy.wait.Done()
	chunks := make(chan latencyChunk, 1024)
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		for chunk := range chunks {
			if wait := time.Until(chunk.deliverAt); wait > 0 {
				timer := time.NewTimer(wait)
				<-timer.C
			}
			if _, err := destination.Write(chunk.data); err != nil {
				return
			}
		}
	}()
	defer func() {
		close(chunks)
		<-writerDone
	}()

	buffer := make([]byte, 256*1024)
	for {
		count, err := source.Read(buffer)
		if count > 0 {
			chunk := latencyChunk{data: bytes.Clone(buffer[:count]), deliverAt: time.Now().Add(delay)}
			select {
			case chunks <- chunk:
			case <-writerDone:
				return
			}
		}
		if err != nil {
			if err != io.EOF {
				return
			}
			return
		}
	}
}
