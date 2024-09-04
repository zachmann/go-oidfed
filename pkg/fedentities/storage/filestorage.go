package storage

import (
	"encoding/json"
	"os"
	"path"
	"slices"
	"sync"

	"github.com/pkg/errors"

	"github.com/zachmann/go-oidfed/internal/utils"
)

// FileStorage is a storage backend for storing things in files
type FileStorage struct {
	files map[string]*file
}

type file struct {
	path  string
	mutex sync.RWMutex
}

// NewFileStorage creates a new FileStorage at the given path
func NewFileStorage(basepath string) *FileStorage {
	return &FileStorage{
		files: map[string]*file{
			"subordinates":          {path: path.Join(basepath, "subordinates.json")},
			"trust_marked_entities": {path: path.Join(basepath, "trust_marked_entities.json")},
		},
	}
}

// subordinateFileStorage is a file based SubordinateStorageBackend
type subordinateFileStorage struct {
	*file
}

// SubordinateStorage returns a file-based SubordinateStorageBackend
func (store *FileStorage) SubordinateStorage() SubordinateStorageBackend {
	return subordinateFileStorage{store.files["subordinates"]}
}

// TrustMarkedEntitiesStorage returns a file-based TrustMarkedEntitiesStorageBackend
func (store *FileStorage) TrustMarkedEntitiesStorage() TrustMarkedEntitiesStorageBackend {
	return trustMarkedEntitiesFileStorage{store.files["trust_marked_entities"]}
}

func (s subordinateFileStorage) readUnlocked() (infos map[string]SubordinateInfo, err error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	err = json.Unmarshal(data, &infos)
	return
}
func (s subordinateFileStorage) writeUnlocked(infos map[string]SubordinateInfo) (err error) {
	data, err := json.Marshal(infos)
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0600)
}

func (s subordinateFileStorage) Write(entityID string, info SubordinateInfo) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	infos, err := s.readUnlocked()
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if infos == nil {
			infos = make(map[string]SubordinateInfo)
		}
	}
	infos[entityID] = info
	return s.writeUnlocked(infos)
}

// Q implements the SubordinateStorageBackend interface and returns a SubordinateStorageQuery
func (s subordinateFileStorage) Q() SubordinateStorageQuery {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	infosMap, err := s.readUnlocked()
	if err != nil {
		return nil
	}
	infos := make([]SubordinateInfo, len(infosMap))
	i := 0
	for _, v := range infosMap {
		infos[i] = v
		i++
	}
	return &simpleSubordinateStorageQuery{
		base: infos,
	}
}

// Delete implements the SubordinateStorageBackend
func (s subordinateFileStorage) Delete(entityID string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	infos, err := s.readUnlocked()
	if err != nil {
		return err
	}
	delete(infos, entityID)
	return s.writeUnlocked(infos)
}

// Load implements the SubordinateStorageBackend
func (subordinateFileStorage) Load() error {
	return nil
}

func addToSliceIfNotExists[C comparable](item C, slice []C) []C {
	if !utils.SliceContains(item, slice) {
		slice = append(slice, item)
	}
	return slice
}

func removeFromSlice[C comparable](item C, slice []C) (out []C) {
	for _, i := range slice {
		if i != item {
			out = append(out, i)
		}
	}
	return
}

// trustMarkedEntitiesFileStorage is a file-based TrustMarkedEntitiesStorageBackend
type trustMarkedEntitiesFileStorage struct {
	*file
}

func (s trustMarkedEntitiesFileStorage) readUnlocked() (infos map[string][]string, err error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	err = json.Unmarshal(data, &infos)
	return
}
func (s trustMarkedEntitiesFileStorage) writeUnlocked(infos map[string][]string) (err error) {
	data, err := json.Marshal(infos)
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0600)
}

func (s trustMarkedEntitiesFileStorage) Write(trustMarkID, entityID string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	infos, err := s.readUnlocked()
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if infos == nil {
			infos = make(map[string][]string)
		}
	}
	tme, ok := infos[trustMarkID]
	if !ok {
		tme = make([]string, 0)
	}
	infos[trustMarkID] = addToSliceIfNotExists(entityID, tme)
	return s.writeUnlocked(infos)
}

// Delete implements the TrustMarkedEntitiesStorageBackend
func (s trustMarkedEntitiesFileStorage) Delete(trustMarkID, entityID string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	infos, err := s.readUnlocked()
	if err != nil {
		return err
	}
	tme, ok := infos[trustMarkID]
	if !ok {
		// If no entities have this trust mark it's fine
		return nil
	}
	infos[trustMarkID] = removeFromSlice(entityID, tme)
	return s.writeUnlocked(infos)
}

// Load implements the TrustMarkedEntitiesStorageBackend
func (s trustMarkedEntitiesFileStorage) Load() error {
	return nil
}

// TrustMarkedEntities implements the TrustMarkedEntitiesStorageBackend
func (s trustMarkedEntitiesFileStorage) TrustMarkedEntities(trustMarkID string) ([]string, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	infosMap, err := s.readUnlocked()
	if err != nil {
		return nil, err
	}
	return infosMap[trustMarkID], nil
}

// HasTrustMark implements the TrustMarkedEntitiesStorageBackend
func (s trustMarkedEntitiesFileStorage) HasTrustMark(trustMarkID, entityID string) (bool, error) {
	tme, err := s.TrustMarkedEntities(trustMarkID)
	if err != nil {
		return false, err
	}
	if tme == nil {
		return false, nil
	}
	return slices.Contains(tme, entityID), nil
}
