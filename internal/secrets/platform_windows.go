//go:build windows

package secrets

func NewPlatformStore() Store {
	return NewWindowsStore()
}
