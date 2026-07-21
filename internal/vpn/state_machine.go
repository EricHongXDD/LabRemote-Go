package vpn

import (
	"sync"
	"time"

	"github.com/EricHongXDD/LabRemote-Go/internal/events"
	"github.com/EricHongXDD/LabRemote-Go/internal/model"
)

type StateMachine struct {
	mu       sync.RWMutex
	statuses map[string]model.VPNStatus
	events   events.Sink
}

func NewStateMachine(sink events.Sink) *StateMachine {
	return &StateMachine{statuses: make(map[string]model.VPNStatus), events: sink}
}

func (s *StateMachine) Set(profileID string, state model.VPNState, errorCode string) model.VPNStatus {
	s.mu.Lock()
	status := s.statuses[profileID]
	status.ProfileID = profileID
	status.State = state
	status.ErrorCode = errorCode
	status.UpdatedAt = time.Now()
	s.statuses[profileID] = status
	s.mu.Unlock()
	s.events.Emit("vpn:status", status)
	return status
}

func (s *StateMachine) Update(profileID string, update func(*model.VPNStatus)) model.VPNStatus {
	s.mu.Lock()
	status := s.statuses[profileID]
	status.ProfileID = profileID
	if status.State == "" {
		status.State = model.VPNDisconnected
	}
	update(&status)
	status.UpdatedAt = time.Now()
	s.statuses[profileID] = status
	s.mu.Unlock()
	s.events.Emit("vpn:status", status)
	return status
}

func (s *StateMachine) Get(profileID string) model.VPNStatus {
	s.mu.RLock()
	status, ok := s.statuses[profileID]
	s.mu.RUnlock()
	if !ok {
		status = model.VPNStatus{ProfileID: profileID, State: model.VPNDisconnected, UpdatedAt: time.Now()}
	}
	return status
}

func validTransition(from, to model.VPNState) bool {
	allowed := map[model.VPNState]map[model.VPNState]bool{
		model.VPNDisconnected:  {model.VPNPreparing: true, model.VPNNotRequired: true},
		model.VPNNotRequired:   {model.VPNDisconnected: true},
		model.VPNPreparing:     {model.VPNDialing: true, model.VPNFailed: true},
		model.VPNDialing:       {model.VPNConnected: true, model.VPNFailed: true},
		model.VPNConnected:     {model.VPNDisconnecting: true, model.VPNReconnecting: true, model.VPNFailed: true},
		model.VPNReconnecting:  {model.VPNConnected: true, model.VPNFailed: true},
		model.VPNDisconnecting: {model.VPNDisconnected: true, model.VPNFailed: true},
		model.VPNFailed:        {model.VPNPreparing: true, model.VPNDisconnected: true},
	}
	return from == to || allowed[from][to]
}
