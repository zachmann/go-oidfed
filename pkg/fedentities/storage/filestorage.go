package storage

import (
	"encoding/json"
	"os"
	"path"
	"slices"
	"sync"

	"github.com/pkg/errors"
	slices2 "tideland.dev/go/slices"

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

// Block implements the SubordinateStorageBackend interface
func (s subordinateFileStorage) Block(entityID string) error {
	return changeSubordinateStatus(entityID, StatusBlocked, s)
}

// Approve implements the SubordinateStorageBackend interface
func (s subordinateFileStorage) Approve(entityID string) error {
	return changeSubordinateStatus(entityID, StatusActive, s)
}

// Subordinate implements the SubordinateStorageBackend interface
func (s subordinateFileStorage) Subordinate(entityID string) (*SubordinateInfo, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	infosMap, err := s.readUnlocked()
	if err != nil {
		return nil, err
	}
	info, ok := infosMap[entityID]
	if !ok {
		return nil, nil
	}
	return &info, nil
}

func (s subordinateFileStorage) withStatus(status Status) SubordinateStorageQuery {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	infosMap, err := s.readUnlocked()
	if err != nil {
		return nil
	}
	var infos []SubordinateInfo
	for _, v := range infosMap {
		if v.Status == status {
			infos = append(infos, v)
		}
	}
	return &simpleSubordinateStorageQuery{
		base: infos,
	}
}

// Active implements the SubordinateStorageBackend interface
func (s subordinateFileStorage) Active() SubordinateStorageQuery {
	return s.withStatus(StatusActive)
}

// Blocked implements the SubordinateStorageBackend interface
func (s subordinateFileStorage) Blocked() SubordinateStorageQuery {
	return s.withStatus(StatusBlocked)
}

// Pending implements the SubordinateStorageBackend interface
func (s subordinateFileStorage) Pending() SubordinateStorageQuery {
	return s.withStatus(StatusPending)
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
	}
	if infos == nil {
		infos = make(map[string]SubordinateInfo)
	}
	infos[entityID] = info
	return s.writeUnlocked(infos)
}

// All returns a SubordinateStorageQuery for all stored SubordinateInfos
func (s subordinateFileStorage) All() SubordinateStorageQuery {
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

func (s trustMarkedEntitiesFileStorage) readUnlocked() (infos map[string]map[Status][]string, err error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	err = json.Unmarshal(data, &infos)
	if err != nil {
		// try to unmarshal legacy file format
		var legacyInfos map[string][]string
		if e := json.Unmarshal(data, &legacyInfos); e != nil {
			return nil, err
		}
		err = nil
		for k, v := range legacyInfos {
			mappedV := map[Status][]string{
				StatusActive: v,
			}
			infos[k] = mappedV
		}
	}
	return
}
func (s trustMarkedEntitiesFileStorage) writeUnlocked(infos map[string]map[Status][]string) (err error) {
	data, err := json.Marshal(infos)
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0600)
}

// Block implements the TrustMarkedEntitiesStorageBackend
func (s trustMarkedEntitiesFileStorage) Block(trustMarkID, entityID string) error {
	return s.write(trustMarkID, entityID, StatusBlocked)
}

// Approve implements the TrustMarkedEntitiesStorageBackend
func (s trustMarkedEntitiesFileStorage) Approve(trustMarkID, entityID string) error {
	return s.write(trustMarkID, entityID, StatusActive)
}

// Request implements the TrustMarkedEntitiesStorageBackend
func (s trustMarkedEntitiesFileStorage) Request(trustMarkID, entityID string) error {
	return s.write(trustMarkID, entityID, StatusPending)
}

// TrustMarkedStatus implements the TrustMarkedEntitiesStorageBackend
func (s trustMarkedEntitiesFileStorage) TrustMarkedStatus(trustMarkID, entityID string) (Status, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	infosMap, err := s.readUnlocked()
	if err != nil {
		return -1, err
	}
	infos, ok := infosMap[trustMarkID]
	if !ok {
		return StatusInactive, nil
	}
	for status, ids := range infos {
		if slices.Contains(ids, entityID) {
			return status, nil
		}
	}
	return StatusInactive, nil
}

func (s trustMarkedEntitiesFileStorage) Active(trustMarkID string) ([]string, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	infosMap, err := s.readUnlocked()
	if err != nil {
		return nil, err
	}
	if trustMarkID != "" {
		infos, ok := infosMap[trustMarkID]
		if !ok {
			return nil, nil
		}
		return infos[StatusActive], nil
	}
	var entityIDs []string
	for _, infos := range infosMap {
		ids, ok := infos[StatusActive]
		if !ok {
			continue
		}
		entityIDs = append(entityIDs, ids...)
	}
	return slices2.Unique(entityIDs), nil

}

func (s trustMarkedEntitiesFileStorage) Blocked(trustMarkID string) ([]string, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	infosMap, err := s.readUnlocked()
	if err != nil {
		return nil, err
	}
	infos, ok := infosMap[trustMarkID]
	if !ok {
		return nil, nil
	}
	return infos[StatusBlocked], nil
}

func (s trustMarkedEntitiesFileStorage) Pending(trustMarkID string) ([]string, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	infosMap, err := s.readUnlocked()
	if err != nil {
		return nil, err
	}
	infos, ok := infosMap[trustMarkID]
	if !ok {
		return nil, nil
	}
	return infos[StatusPending], nil
}

func (s trustMarkedEntitiesFileStorage) write(trustMarkID, entityID string, status Status) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	infos, err := s.readUnlocked()
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if infos == nil {
		infos = make(map[string]map[Status][]string)
	}
	tme, ok := infos[trustMarkID]
	if !ok {
		tme = make(map[Status][]string)
	}
	// remove entityID from other status
	for st, entities := range tme {
		if st != status {
			tme[st] = removeFromSlice(entityID, entities)
		}
	}
	// add entityID to correct status
	entities, ok := tme[status]
	if !ok {
		entities = make([]string, 0)
	}
	entities = addToSliceIfNotExists(entityID, entities)
	tme[status] = entities

	infos[trustMarkID] = tme
	return s.writeUnlocked(infos)
}

// Delete implements the TrustMarkedEntitiesStorageBackend
func (s trustMarkedEntitiesFileStorage) Delete(trustMarkID, entityID string) error {
	return s.write(trustMarkID, entityID, -1)
}

// Load implements the TrustMarkedEntitiesStorageBackend
func (s trustMarkedEntitiesFileStorage) Load() error {
	return nil
}

// HasTrustMark implements the TrustMarkedEntitiesStorageBackend
func (s trustMarkedEntitiesFileStorage) HasTrustMark(trustMarkID, entityID string) (bool, error) {
	tme, err := s.Active(trustMarkID)
	if err != nil {
		return false, err
	}
	if tme == nil {
		return false, nil
	}
	return slices.Contains(tme, entityID), nil
}
