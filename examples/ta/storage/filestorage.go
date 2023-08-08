package storage

import (
	"encoding/json"
	"os"
	"path"

	"github.com/pkg/errors"

	"github.com/zachmann/go-oidcfed/examples/ta/config"
)

type JWKSFileStorage map[string]SubordinateInfo

var storageFile string

func (store JWKSFileStorage) Load() error {
	storageFile = path.Join(config.Get().DataLocation, "jwks.store")
	data, err := os.ReadFile(storageFile)
	if err != nil {
		return nil
	}
	return json.Unmarshal(data, &store)
}

func (store JWKSFileStorage) Write(entityID string, info SubordinateInfo) error {
	(store)[entityID] = info
	data, err := json.Marshal(store)
	if err != nil {
		return err
	}
	return os.WriteFile(storageFile, data, 0600)
}

func (store JWKSFileStorage) Read(entityID string) (SubordinateInfo, error) {
	info, ok := store[entityID]
	if !ok {
		return SubordinateInfo{}, errors.Errorf("'%s' not found", entityID)
	}
	return info, nil
}
func (store JWKSFileStorage) ListSubordinates(entityType string) (entities []string, err error) {
	for k, info := range store {
		if entityType == "" || entityType == info.EntityType {
			entities = append(entities, k)
		}
	}
	return
}
