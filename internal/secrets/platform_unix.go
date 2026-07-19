//go:build linux || darwin

package secrets

func NewPlatformStore() Store {
	return NewKeyringStore()
}
