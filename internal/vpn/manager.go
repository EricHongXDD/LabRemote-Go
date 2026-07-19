package vpn

import (
	"context"
	"net"

	"github.com/EricHongXDD/LabRemote-Go/internal/model"
)

type Manager interface {
	EnsureProfile(ctx context.Context, profile model.ConnectionProfile) error
	Connect(ctx context.Context, profileID string) (model.VPNStatus, error)
	Status(ctx context.Context, profileID string) (model.VPNStatus, error)
	Disconnect(ctx context.Context, profileID string, force bool) error
}

type Transport interface {
	Manager
	DialContext(ctx context.Context, profileID, network, address string) (net.Conn, error)
	AcceptCertificate(ctx context.Context, profileID, fingerprint string) error
	Shutdown(ctx context.Context)
}
