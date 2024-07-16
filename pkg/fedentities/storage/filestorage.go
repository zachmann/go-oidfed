package storage

import (
	"encoding/json"
	"os"
	"path"
	"sync"

	"github.com/pkg/errors"
)

type FileStorage struct {
	files map[string]*file
}

type file struct {
	path  string
	mutex sync.RWMutex
}

type subordinateFileStorage struct {
	*file
}

func NewFileStorage(basepath string) *FileStorage {
	return &FileStorage{
		files: map[string]*file{
			"subordinates": {path: path.Join(basepath, "subordinates.json")},
		},
	}
}

func (s subordinateFileStorage) readUnlocked() (infos map[string]SubordinateInfo, err error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
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

func (subordinateFileStorage) Load() error {
	return nil
}

func (store *FileStorage) SubordinateStorage() SubordinateStorageBackend {
	return subordinateFileStorage{store.files["subordinates"]}
}
