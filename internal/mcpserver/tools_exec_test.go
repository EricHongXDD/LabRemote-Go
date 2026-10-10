package mcpserver

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/EricHongXDD/LabRemote-Go/internal/model"
	"github.com/EricHongXDD/LabRemote-Go/internal/secrets"
)

type stalledExecCore struct{ lifecycleCore }

func (c *stalledExecCore) MCPExec(ctx context.Context, request model.ExecRequest) (model.ExecResult, error) {
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > request.Timeout {
		return model.ExecResult{}, model.NewAppError("TEST_NO_DEADLINE", "整个调用缺少超时", "test", false)
	}
	<-ctx.Done()
	return model.ExecResult{}, ctx.Err()
}

func TestSSHExecDeadlineReleasesAllBusySlots(t *testing.T) {
	controller := NewController(&stalledExecCore{}, secrets.NewMemoryStore(), NewAuditor(slog.New(slog.NewTextHandler(io.Discard, nil))))
	var workers sync.WaitGroup
	for index := 0; index < cap(controller.execSlots); index++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			_, _, err := controller.sshExec(context.Background(), nil, execInput{ProfileID: "test", Command: "test", TimeoutSeconds: 1})
			if err == nil {
				t.Error("挂起的调用应超时")
			}
		}()
	}
	workers.Wait()
	if len(controller.execSlots) != 0 {
		t.Fatalf("超时后名额未释放: %d", len(controller.execSlots))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err := controller.sshExec(ctx, nil, execInput{ProfileID: "test", Command: "test"})
	if appErrorCode(err) == "MCP_BUSY" {
		t.Fatal("后续调用不应持续返回 MCP_BUSY")
	}
}
