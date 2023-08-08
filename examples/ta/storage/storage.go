package storage

import (
	"github.com/lestrrat-go/jwx/jwk"
)

type SubordinateInfo struct {
	JWKS       jwk.Set `json:"jwks"`
	EntityType string  `json:"entity_type"`
	EntityID   string  `json:"entity_id"`
}

type JWKStorageBackend interface {
	Write(entityID string, info SubordinateInfo) error
	Read(entityID string) (SubordinateInfo, error)
	ListSubordinates(entityType string) ([]string, error)
	Load() error
}
