//go:build windows

package secrets

import (
	"context"
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	credTypeGeneric         = 1
	credPersistLocalMachine = 2
)

var (
	advapi32       = windows.NewLazySystemDLL("advapi32.dll")
	procCredWrite  = advapi32.NewProc("CredWriteW")
	procCredRead   = advapi32.NewProc("CredReadW")
	procCredDelete = advapi32.NewProc("CredDeleteW")
	procCredFree   = advapi32.NewProc("CredFree")
)

type credential struct {
	Flags              uint32
	Type               uint32
	TargetName         *uint16
	Comment            *uint16
	LastWritten        windows.Filetime
	CredentialBlobSize uint32
	CredentialBlob     *byte
	Persist            uint32
	AttributeCount     uint32
	Attributes         uintptr
	TargetAlias        *uint16
	UserName           *uint16
}

type WindowsStore struct{}

func NewWindowsStore() *WindowsStore { return &WindowsStore{} }

func (s *WindowsStore) Put(_ context.Context, key string, secret []byte) error {
	target, err := windows.UTF16PtrFromString(key)
	if err != nil {
		return fmt.Errorf("凭据名称无效: %w", err)
	}
	user, _ := windows.UTF16PtrFromString("LabRemote")
	value := append([]byte(nil), secret...)
	defer Zero(value)
	entry := credential{
		Type:               credTypeGeneric,
		TargetName:         target,
		CredentialBlobSize: uint32(len(value)),
		Persist:            credPersistLocalMachine,
		UserName:           user,
	}
	if len(value) > 0 {
		entry.CredentialBlob = &value[0]
	}
	result, _, callErr := procCredWrite.Call(uintptr(unsafe.Pointer(&entry)), 0)
	if result == 0 {
		return fmt.Errorf("写入 Windows 凭据失败: %w", callErr)
	}
	return nil
}

func (s *WindowsStore) Get(_ context.Context, key string) ([]byte, error) {
	target, err := windows.UTF16PtrFromString(key)
	if err != nil {
		return nil, fmt.Errorf("凭据名称无效: %w", err)
	}
	var entry *credential
	result, _, callErr := procCredRead.Call(
		uintptr(unsafe.Pointer(target)),
		credTypeGeneric,
		0,
		uintptr(unsafe.Pointer(&entry)),
	)
	if result == 0 {
		if errors.Is(callErr, syscall.ERROR_NOT_FOUND) || errors.Is(callErr, windows.ERROR_NOT_FOUND) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("读取 Windows 凭据失败: %w", callErr)
	}
	defer procCredFree.Call(uintptr(unsafe.Pointer(entry)))
	if entry == nil || entry.CredentialBlobSize == 0 {
		return []byte{}, nil
	}
	value := unsafe.Slice(entry.CredentialBlob, int(entry.CredentialBlobSize))
	return append([]byte(nil), value...), nil
}

func (s *WindowsStore) Delete(_ context.Context, key string) error {
	target, err := windows.UTF16PtrFromString(key)
	if err != nil {
		return fmt.Errorf("凭据名称无效: %w", err)
	}
	result, _, callErr := procCredDelete.Call(uintptr(unsafe.Pointer(target)), credTypeGeneric, 0)
	if result == 0 && !errors.Is(callErr, syscall.ERROR_NOT_FOUND) && !errors.Is(callErr, windows.ERROR_NOT_FOUND) {
		return fmt.Errorf("删除 Windows 凭据失败: %w", callErr)
	}
	return nil
}
