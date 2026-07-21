package vpn

import (
	"testing"

	"github.com/EricHongXDD/LabRemote-Go/internal/events"
	"github.com/EricHongXDD/LabRemote-Go/internal/model"
)

func TestVPNStateTransitions(t *testing.T) {
	valid := [][2]model.VPNState{
		{model.VPNDisconnected, model.VPNNotRequired},
		{model.VPNNotRequired, model.VPNDisconnected},
		{model.VPNDisconnected, model.VPNPreparing},
		{model.VPNPreparing, model.VPNDialing},
		{model.VPNDialing, model.VPNConnected},
		{model.VPNConnected, model.VPNDisconnecting},
		{model.VPNDisconnecting, model.VPNDisconnected},
	}
	for _, pair := range valid {
		if !validTransition(pair[0], pair[1]) {
			t.Fatalf("应允许状态转换 %s -> %s", pair[0], pair[1])
		}
	}
	if validTransition(model.VPNDisconnected, model.VPNConnected) {
		t.Fatal("不应跳过准备和拨号状态")
	}
	machine := NewStateMachine(events.Nop{})
	if status := machine.Set("profile", model.VPNPreparing, ""); status.State != model.VPNPreparing {
		t.Fatalf("状态保存失败: %#v", status)
	}
}
