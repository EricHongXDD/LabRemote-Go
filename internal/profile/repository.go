package profile

import (
	"context"

	"github.com/EricHongXDD/LabRemote-Go/internal/model"
)

type Repository interface {
	List(ctx context.Context) ([]model.ConnectionProfile, error)
	Get(ctx context.Context, id string) (model.ConnectionProfile, error)
	Upsert(ctx context.Context, value model.ConnectionProfile) error
	Delete(ctx context.Context, id string) error
}
