package openvpn

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/EricHongXDD/LabRemote-Go/internal/events"
	"github.com/google/uuid"
)

type Challenge struct {
	ID          string `json:"id"`
	ProfileID   string `json:"profile_id"`
	ProfileName string `json:"profile_name"`
	Prompt      string `json:"prompt"`
	Username    string `json:"username"`
}

type OTPBroker struct {
	mu      sync.Mutex
	pending map[string]chan string
	events  events.Sink
}

func NewOTPBroker(sink events.Sink) *OTPBroker {
	if sink == nil {
		sink = events.Nop{}
	}
	return &OTPBroker{pending: make(map[string]chan string), events: sink}
}

func (b *OTPBroker) Request(ctx context.Context, challenge Challenge) (string, error) {
	challenge.ID = uuid.NewString()
	response := make(chan string, 1)
	b.mu.Lock()
	b.pending[challenge.ID] = response
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		delete(b.pending, challenge.ID)
		b.mu.Unlock()
		b.events.Emit("openvpn:otp-closed", map[string]string{"id": challenge.ID})
	}()
	b.events.Emit("openvpn:otp", challenge)
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case code := <-response:
		if code == "" {
			return "", fmt.Errorf("已取消验证码输入")
		}
		return code, nil
	}
}

// Submit 空字符串表示取消，验证码只交给当前请求，不写入配置、凭据或事件。
func (b *OTPBroker) Submit(id, code string) error {
	code = strings.TrimSpace(code)
	if code != "" {
		if len(code) != 6 {
			return fmt.Errorf("请输入 6 位数字验证码")
		}
		for _, c := range code {
			if c < '0' || c > '9' {
				return fmt.Errorf("请输入 6 位数字验证码")
			}
		}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	response := b.pending[id]
	if response == nil {
		return fmt.Errorf("验证码请求已结束，请重新连接")
	}
	select {
	case response <- code:
		delete(b.pending, id)
		return nil
	default:
		return fmt.Errorf("验证码已提交")
	}
}
