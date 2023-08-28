package storage

import (
	"encoding/json"

	"github.com/lestrrat-go/jwx/jwk"
)

type SubordinateInfo struct {
	JWKS       jwk.Set `json:"jwks"`
	EntityType string  `json:"entity_type"`
	EntityID   string  `json:"entity_id"`
}

func (info *SubordinateInfo) UnmarshalJSON(src []byte) error {
	type subordinateInfo SubordinateInfo
	ii := subordinateInfo(*info)
	if ii.JWKS == nil {
		ii.JWKS = jwk.NewSet()
	}
	if err := json.Unmarshal(src, &ii); err != nil {
		return err
	}
	if ii.JWKS.Len() == 0 {
		ii.JWKS = nil
	}
	*info = SubordinateInfo(ii)
	return nil
}

type JWKStorageBackend interface {
	Write(entityID string, info SubordinateInfo) error
	Read(entityID string) (SubordinateInfo, error)
	ListSubordinates(entityType string) ([]string, error)
	Load() error
}
