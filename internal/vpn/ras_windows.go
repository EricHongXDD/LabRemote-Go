//go:build windows && legacy_ras

package vpn

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/EricHongXDD/LabRemote-Go/internal/secrets"
	"golang.org/x/sys/windows"
)

const (
	rasCredentialUserName     = 0x00000001
	rasCredentialPassword     = 0x00000002
	rasCredentialPreSharedKey = 0x00000010
	errorBufferTooSmall       = 603
	rasStateConnected         = 0x2000
)

var (
	rasapi32                   = windows.NewLazySystemDLL("rasapi32.dll")
	procRasDial                = rasapi32.NewProc("RasDialW")
	procRasHangUp              = rasapi32.NewProc("RasHangUpW")
	procRasSetCredentials      = rasapi32.NewProc("RasSetCredentialsW")
	procRasSetEntryProperties  = rasapi32.NewProc("RasSetEntryPropertiesW")
	procRasEnumConnections     = rasapi32.NewProc("RasEnumConnectionsW")
	procRasGetConnectStatus    = rasapi32.NewProc("RasGetConnectStatusW")
	procRasGetProjectionInfoEx = rasapi32.NewProc("RasGetProjectionInfoEx")
)

func copyUTF16(destination []uint16, source string) error {
	value, err := windows.UTF16FromString(source)
	if err != nil {
		return err
	}
	if len(value) > len(destination) {
		return fmt.Errorf("文本长度超过 Windows RAS 字段限制")
	}
	copy(destination, value)
	return nil
}

func setRASCredentials(entryName, username string, password []byte) error {
	entry, err := windows.UTF16PtrFromString(entryName)
	if err != nil {
		return err
	}
	credentials := newRasCredentials()
	credentials.Mask = rasCredentialUserName | rasCredentialPassword
	if err := copyUTF16(credentials.UserName[:], username); err != nil {
		return err
	}
	passwordText := string(password)
	defer func() {
		for index := range credentials.Password {
			credentials.Password[index] = 0
		}
	}()
	if err := copyUTF16(credentials.Password[:], passwordText); err != nil {
		return err
	}
	result, _, _ := procRasSetCredentials.Call(0, uintptr(unsafe.Pointer(entry)), uintptr(unsafe.Pointer(&credentials)), 0)
	if result != 0 {
		return mapRASError(uint32(result))
	}
	return nil
}

func setRASPreSharedKey(entryName string, preSharedKey []byte) error {
	entry, err := windows.UTF16PtrFromString(entryName)
	if err != nil {
		return err
	}
	credentials := newRasCredentials()
	credentials.Mask = rasCredentialPreSharedKey
	preSharedKeyText := string(preSharedKey)
	if err := copyUTF16(credentials.Password[:], preSharedKeyText); err != nil {
		return err
	}
	defer func() {
		for index := range credentials.Password {
			credentials.Password[index] = 0
		}
	}()
	result, _, _ := procRasSetCredentials.Call(0, uintptr(unsafe.Pointer(entry)), uintptr(unsafe.Pointer(&credentials)), 0)
	if result != 0 {
		return mapRASError(uint32(result))
	}
	return nil
}

// setRASEntryProperties 封装 RasSetEntryPropertiesW。当前创建 L2TP 条目时优先使用
// Windows VPNClient Provider，以避免依赖本地化的 WAN Miniport 设备名；此封装用于后续
// 在已解析设备名时直接更新 RAS Phone Book。
func setRASEntryProperties(entryName string, entry *rasEntry) error {
	name, err := windows.UTF16PtrFromString(entryName)
	if err != nil {
		return err
	}
	result, _, _ := procRasSetEntryProperties.Call(0, uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(entry)), uintptr(entry.Size), 0, 0)
	if result != 0 {
		return fmt.Errorf("RasSetEntryPropertiesW 失败，错误码 %d", result)
	}
	return nil
}

func enumRASConnections() ([]rasConnection, error) {
	connections := []rasConnection{newRasConnection()}
	bufferSize := uint32(unsafe.Sizeof(connections[0]))
	var count uint32
	result, _, _ := procRasEnumConnections.Call(
		uintptr(unsafe.Pointer(&connections[0])),
		uintptr(unsafe.Pointer(&bufferSize)),
		uintptr(unsafe.Pointer(&count)),
	)
	if uint32(result) == errorBufferTooSmall {
		needed := int(bufferSize / uint32(unsafe.Sizeof(connections[0])))
		if needed < 1 {
			needed = 1
		}
		connections = make([]rasConnection, needed)
		for index := range connections {
			connections[index] = newRasConnection()
		}
		result, _, _ = procRasEnumConnections.Call(
			uintptr(unsafe.Pointer(&connections[0])),
			uintptr(unsafe.Pointer(&bufferSize)),
			uintptr(unsafe.Pointer(&count)),
		)
	}
	if result != 0 {
		return nil, fmt.Errorf("RasEnumConnectionsW 失败，错误码 %d", result)
	}
	if int(count) < len(connections) {
		connections = connections[:count]
	}
	return connections, nil
}

func findRASConnection(entryName string) (rasConnection, bool, error) {
	connections, err := enumRASConnections()
	if err != nil {
		return rasConnection{}, false, err
	}
	for _, connection := range connections {
		if windows.UTF16ToString(connection.EntryName[:]) == entryName {
			return connection, true, nil
		}
	}
	return rasConnection{}, false, nil
}

func getRASConnectStatus(handle uintptr) (rasConnectStatus, error) {
	status := newRasConnectStatus()
	result, _, _ := procRasGetConnectStatus.Call(handle, uintptr(unsafe.Pointer(&status)))
	if result != 0 {
		return status, fmt.Errorf("RasGetConnectStatusW 失败，错误码 %d", result)
	}
	return status, nil
}

func getRASProjectionInfo(handle uintptr) (rasProjectionInfo, error) {
	info := rasProjectionInfo{Version: 1}
	size := uint32(unsafe.Sizeof(info))
	result, _, _ := procRasGetProjectionInfoEx.Call(handle, uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&size)))
	if result != 0 {
		return info, fmt.Errorf("RasGetProjectionInfoEx 失败，错误码 %d", result)
	}
	return info, nil
}

func dialRAS(ctx context.Context, entryName, username string, password []byte) (uintptr, error) {
	params := newRasDialParams()
	if err := copyUTF16(params.EntryName[:], entryName); err != nil {
		return 0, err
	}
	if err := copyUTF16(params.UserName[:], username); err != nil {
		return 0, err
	}
	passwordText := string(password)
	if err := copyUTF16(params.Password[:], passwordText); err != nil {
		return 0, err
	}
	defer func() {
		for index := range params.Password {
			params.Password[index] = 0
		}
		secrets.Zero(password)
	}()
	var handle uintptr
	resultChannel := make(chan uint32, 1)
	go func() {
		result, _, _ := procRasDial.Call(0, 0, uintptr(unsafe.Pointer(&params)), 0, 0, uintptr(unsafe.Pointer(&handle)))
		resultChannel <- uint32(result)
	}()
	select {
	case result := <-resultChannel:
		if result != 0 {
			return 0, mapRASError(result)
		}
		return handle, nil
	case <-ctx.Done():
		if current := atomic.LoadUintptr(&handle); current != 0 {
			procRasHangUp.Call(current)
		}
		return 0, ctx.Err()
	case <-time.After(30 * time.Second):
		if current := atomic.LoadUintptr(&handle); current != 0 {
			procRasHangUp.Call(current)
		}
		return 0, fmt.Errorf("VPN 拨号超时")
	}
}

func hangUpRAS(handle uintptr) error {
	if handle == 0 {
		return nil
	}
	result, _, _ := procRasHangUp.Call(handle)
	if result != 0 {
		return fmt.Errorf("断开 Windows VPN 失败，RAS 错误码 %d", result)
	}
	return nil
}
