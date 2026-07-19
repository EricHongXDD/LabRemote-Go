//go:build windows && legacy_ras

package vpn

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	rasMaxEntryName      = 256
	rasMaxPhoneNumber    = 128
	rasMaxCallbackNumber = 128
	windowsUNLen         = 256
	windowsPWLen         = 256
	windowsDNLen         = 15
	rasMaxDeviceType     = 16
	rasMaxDeviceName     = 128
)

type rasDialParams struct {
	Size           uint32
	EntryName      [rasMaxEntryName + 1]uint16
	PhoneNumber    [rasMaxPhoneNumber + 1]uint16
	CallbackNumber [rasMaxCallbackNumber + 1]uint16
	UserName       [windowsUNLen + 1]uint16
	Password       [windowsPWLen + 1]uint16
	Domain         [windowsDNLen + 1]uint16
	SubEntry       uint32
	CallbackID     uintptr
	IfIndex        uint32
}

type rasCredentials struct {
	Size     uint32
	Mask     uint32
	UserName [windowsUNLen + 1]uint16
	Password [windowsPWLen + 1]uint16
	Domain   [windowsDNLen + 1]uint16
}

type rasIPAddr struct {
	A byte
	B byte
	C byte
	D byte
}

type rasEntry struct {
	Size                      uint32
	Options                   uint32
	CountryID                 uint32
	CountryCode               uint32
	AreaCode                  [11]uint16
	LocalPhoneNumber          [129]uint16
	AlternateOffset           uint32
	IPAddress                 rasIPAddr
	DNSAddress                rasIPAddr
	AlternateDNSAddress       rasIPAddr
	WINSAddress               rasIPAddr
	AlternateWINSAddress      rasIPAddr
	FrameSize                 uint32
	NetworkProtocols          uint32
	FramingProtocol           uint32
	Script                    [260]uint16
	AutodialDLL               [260]uint16
	AutodialFunction          [260]uint16
	DeviceType                [17]uint16
	DeviceName                [129]uint16
	X25PadType                [33]uint16
	X25Address                [201]uint16
	X25Facilities             [201]uint16
	X25UserData               [201]uint16
	Channels                  uint32
	Reserved1                 uint32
	Reserved2                 uint32
	SubEntries                uint32
	DialMode                  uint32
	DialExtraPercent          uint32
	DialExtraSampleSeconds    uint32
	HangUpExtraPercent        uint32
	HangUpExtraSampleSeconds  uint32
	IdleDisconnectSeconds     uint32
	Type                      uint32
	EncryptionType            uint32
	CustomAuthKey             uint32
	ID                        windows.GUID
	CustomDialDLL             [260]uint16
	VPNStrategy               uint32
	Options2                  uint32
	Options3                  uint32
	DNSSuffix                 [256]uint16
	TCPWindowSize             uint32
	PrerequisitePhonebook     [260]uint16
	PrerequisiteEntry         [257]uint16
	RedialCount               uint32
	RedialPause               uint32
	IPv6DNSAddress            [16]byte
	IPv6AlternateDNSAddress   [16]byte
	IPv4InterfaceMetric       uint32
	IPv6InterfaceMetric       uint32
	IPv6Address               [16]byte
	IPv6PrefixLength          uint32
	NetworkOutageTime         uint32
	IDi                       [257]uint16
	IDr                       [257]uint16
	IsIMSConfig               int32
	IDiType                   uint32
	IDrType                   uint32
	DisableIKEv2Fragmentation int32
}

type rasLUID struct {
	LowPart  uint32
	HighPart int32
}

type rasConnection struct {
	Size          uint32
	Handle        uintptr
	EntryName     [rasMaxEntryName + 1]uint16
	DeviceType    [rasMaxDeviceType + 1]uint16
	DeviceName    [rasMaxDeviceName + 1]uint16
	Phonebook     [260]uint16
	SubEntry      uint32
	EntryID       windows.GUID
	Flags         uint32
	LogonID       rasLUID
	CorrelationID windows.GUID
}

type rasTunnelEndpoint struct {
	Type    uint32
	Address [16]byte
}

type rasConnectStatus struct {
	Size           uint32
	State          uint32
	Error          uint32
	DeviceType     [rasMaxDeviceType + 1]uint16
	DeviceName     [rasMaxDeviceName + 1]uint16
	PhoneNumber    [rasMaxPhoneNumber + 1]uint16
	LocalEndpoint  rasTunnelEndpoint
	RemoteEndpoint rasTunnelEndpoint
	SubState       uint32
}

type rasProjectionInfo struct {
	Version uint32
	Type    uint32
	Data    [2048]byte
}

func newRasDialParams() rasDialParams {
	value := rasDialParams{}
	value.Size = uint32(unsafe.Sizeof(value))
	return value
}

func newRasCredentials() rasCredentials {
	value := rasCredentials{}
	value.Size = uint32(unsafe.Sizeof(value))
	return value
}

func newRasEntry() rasEntry {
	value := rasEntry{}
	value.Size = uint32(unsafe.Sizeof(value))
	return value
}

func newRasConnection() rasConnection {
	value := rasConnection{}
	value.Size = uint32(unsafe.Sizeof(value))
	return value
}

func newRasConnectStatus() rasConnectStatus {
	value := rasConnectStatus{}
	value.Size = uint32(unsafe.Sizeof(value))
	return value
}
