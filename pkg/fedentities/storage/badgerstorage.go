package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/dgraph-io/badger/v4"
)

// NewBadgerStorage creates a new BadgerStorage at the passed storage location
func NewBadgerStorage(path string) (*BadgerStorage, error) {
	storage := &BadgerStorage{Path: path}
	err := storage.Load()
	return storage, err
}

// BadgerStorage is a type for a simple database storage backend -
type BadgerStorage struct {
	*badger.DB
	Path   string
	loaded bool
}

// SubordinateStorage gives a SubordinateBadgerStorage
func (store *BadgerStorage) SubordinateStorage() *SubordinateBadgerStorage {
	return &SubordinateBadgerStorage{
		store: &BadgerSubStorage{
			db:     store,
			subKey: "subordinates",
		},
	}
}

// TrustMarkedEntitiesStorage gives a TrustMarkedEntitiesBadgerStorage
func (store *BadgerStorage) TrustMarkedEntitiesStorage() *TrustMarkedEntitiesBadgerStorage {
	return &TrustMarkedEntitiesBadgerStorage{
		store: &BadgerSubStorage{
			db:     store,
			subKey: "subordinates",
		},
	}
}

// Write writes a value to the database
func (store *BadgerStorage) Write(key string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	err = store.Update(
		func(txn *badger.Txn) error {
			return txn.Set([]byte(key), data)
		},
	)
	return err
}

// Delete deletes the value associated with the given key from the database
func (store *BadgerStorage) Delete(key string) error {
	return store.Update(
		func(txn *badger.Txn) error {
			return txn.Delete([]byte(key))
		},
	)
}

// Read reads the value for a given key into target
func (store *BadgerStorage) Read(key string, target any) (bool, error) {
	var notFound bool
	err := store.View(
		func(txn *badger.Txn) error {
			item, err := txn.Get([]byte(key))
			if errors.Is(err, badger.ErrKeyNotFound) {
				notFound = true
				return fmt.Errorf("'%s' not found", key)
			}

			return item.Value(
				func(val []byte) error {
					return json.Unmarshal(val, target)
				},
			)
		},
	)
	return !notFound, err
}

// BadgerSubStorage is a type for a sub-storage of a BadgerStorage
type BadgerSubStorage struct {
	db     *BadgerStorage
	subKey string
}

// Load loads the database
func (store *BadgerSubStorage) Load() error {
	return store.db.Load()
}
func (store *BadgerSubStorage) key(key string) string {
	return fmt.Sprintf(store.subKey + ":" + key)
}

// Write writes a values to the sub-database
func (store *BadgerSubStorage) Write(key string, value any) error {
	return store.db.Write(store.key(key), value)
}

// Delete deletes the value associated with the given key from the sub-database
func (store *BadgerSubStorage) Delete(key string) error {
	return store.db.Delete(store.key(key))
}

// Read reads the value for a given key into target
func (store *BadgerSubStorage) Read(key string, target any) (bool, error) {
	return store.db.Read(store.key(key), target)
}

// ReadIterator uses the passed iterator function do iterate over all the key-value-pairs in this sub storage
func (store *BadgerSubStorage) ReadIterator(do func(k, v []byte) error, prefix ...string) error {
	var prfx string
	if len(prefix) > 0 {
		prfx = prefix[0]
	}
	return store.db.View(
		func(txn *badger.Txn) error {
			it := txn.NewIterator(badger.DefaultIteratorOptions)
			defer it.Close()
			scanPrefix := []byte(store.subKey + ":" + prfx)
			for it.Seek(scanPrefix); it.ValidForPrefix(scanPrefix); it.Next() {
				item := it.Item()
				k := item.Key()
				err := item.Value(
					func(v []byte) error {
						return do(k, v)
					},
				)
				if err != nil {
					return err
				}
			}
			return nil
		},
	)
}

// Load loads the database
func (store *BadgerStorage) Load() error {
	if store.loaded {
		return nil
	}
	db, err := badger.Open(badger.DefaultOptions(store.Path))
	if err != nil {
		return err
	}
	store.DB = db

	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
		again:
			err := db.RunValueLogGC(0.7)
			if err == nil {
				goto again
			}
		}
	}()
	store.loaded = true
	return nil
}

// SubordinateBadgerStorage is a type implementing the SubordinateStorageBackend interface
type SubordinateBadgerStorage struct {
	store *BadgerSubStorage
}

// Load implements the SubordinateStorageBackend interface
func (store *SubordinateBadgerStorage) Load() error {
	return store.store.Load()
}

// Write implements the SubordinateStorageBackend interface
func (store *SubordinateBadgerStorage) Write(entityID string, info SubordinateInfo) error {
	return store.store.Write(entityID, info)
}

// Delete implements the SubordinateStorageBackend interface
func (store *SubordinateBadgerStorage) Delete(entityID string) error {
	return store.store.Delete(entityID)
}

// Read implements the SubordinateStorageBackend interface
func (store *SubordinateBadgerStorage) Read(entityID string) (*SubordinateInfo, error) {
	var info SubordinateInfo
	found, err := store.store.Read(entityID, &info)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	return &info, nil
}

// Block implements the SubordinateStorageBackend interface
func (store *SubordinateBadgerStorage) Block(entityID string) error {
	return changeSubordinateStatus(entityID, StatusBlocked, store)
}

// Approve implements the SubordinateStorageBackend interface
func (store *SubordinateBadgerStorage) Approve(entityID string) error {
	return changeSubordinateStatus(entityID, StatusActive, store)
}

// Subordinate implements the SubordinateStorageBackend interface
func (store *SubordinateBadgerStorage) Subordinate(entityID string) (*SubordinateInfo, error) {
	return store.Read(entityID)
}

// Active implements the SubordinateStorageBackend interface
func (store *SubordinateBadgerStorage) Active() SubordinateStorageQuery {
	return &BadgerSubordinateStorageQuery{
		db: store,
		filters: []func(info SubordinateInfo) bool{
			func(info SubordinateInfo) bool {
				return info.Status == StatusActive
			},
		},
	}
}

// Blocked implements the SubordinateStorageBackend interface
func (store *SubordinateBadgerStorage) Blocked() SubordinateStorageQuery {
	return &BadgerSubordinateStorageQuery{
		db: store,
		filters: []func(info SubordinateInfo) bool{
			func(info SubordinateInfo) bool {
				return info.Status == StatusBlocked
			},
		},
	}
}

// Pending implements the SubordinateStorageBackend interface
func (store *SubordinateBadgerStorage) Pending() SubordinateStorageQuery {
	return &BadgerSubordinateStorageQuery{
		db: store,
		filters: []func(info SubordinateInfo) bool{
			func(info SubordinateInfo) bool {
				return info.Status == StatusPending
			},
		},
	}
}

// All returns a SubordinateStorageQuery for all stored SubordinateInfos
func (store *SubordinateBadgerStorage) All() SubordinateStorageQuery {
	return &BadgerSubordinateStorageQuery{db: store}
}

// BadgerSubordinateStorageQuery is a type implementing the SubordinateStorageQuery interface for a
// SubordinateBadgerStorage
type BadgerSubordinateStorageQuery struct {
	db      *SubordinateBadgerStorage
	filters []func(info SubordinateInfo) bool
}

// Subordinate implements the SubordinateStorageQuery interface
func (q BadgerSubordinateStorageQuery) Subordinate(entityID string) (*SubordinateInfo, error) {
	return q.db.Read(entityID)
}

// Subordinates implements the SubordinateStorageQuery interface
func (q BadgerSubordinateStorageQuery) Subordinates() (infos []SubordinateInfo, err error) {
	err = q.db.store.ReadIterator(
		func(_, v []byte) error {
			var info SubordinateInfo
			if err = json.Unmarshal(v, &info); err != nil {
				return err
			}
			infos = append(infos, info)
			return nil
		},
	)
	return
}

// EntityIDs implements the SubordinateStorageQuery interface
func (q BadgerSubordinateStorageQuery) EntityIDs() (ids []string, err error) {
	err = q.db.store.ReadIterator(
		func(_, v []byte) error {
			var info SubordinateInfo
			if err = json.Unmarshal(v, &info); err != nil {
				return err
			}
			ids = append(ids, info.EntityID)
			return nil
		},
	)
	return
}

// AddFilter implements the SubordinateStorageQuery interface
func (q *BadgerSubordinateStorageQuery) AddFilter(filter SubordinateStorageQueryFilter, value any) error {
	q.filters = append(
		q.filters, func(info SubordinateInfo) bool {
			return filter(info, value)
		},
	)
	return nil

}

// TrustMarkedEntitiesBadgerStorage is a type implementing the TrustMarkedEntitiesStorageBackend interface
type TrustMarkedEntitiesBadgerStorage struct {
	store *BadgerSubStorage
}

// Block implements the TrustMarkedEntitiesStorageBackend interface
func (store *TrustMarkedEntitiesBadgerStorage) Block(trustMarkID, entityID string) error {
	return store.write(trustMarkID, entityID, StatusBlocked)
}

// Approve implements the TrustMarkedEntitiesStorageBackend interface
func (store *TrustMarkedEntitiesBadgerStorage) Approve(trustMarkID, entityID string) error {
	return store.write(trustMarkID, entityID, StatusActive)
}

// Request implements the TrustMarkedEntitiesStorageBackend interface
func (store *TrustMarkedEntitiesBadgerStorage) Request(trustMarkID, entityID string) error {
	return store.write(trustMarkID, entityID, StatusPending)
}

// TrustMarkedStatus implements the TrustMarkedEntitiesStorageBackend interface
func (store *TrustMarkedEntitiesBadgerStorage) TrustMarkedStatus(trustMarkID, entityID string) (Status, error) {
	var status Status
	var id string
	k := store.key(trustMarkID, entityID)
	found, err := store.store.Read(k, &status)
	if err != nil {
		found, e := store.store.Read(k, &id)
		if e == nil && found {
			return StatusActive, nil
		}
		return -1, err
	}
	if !found {
		return StatusInactive, nil
	}
	return status, nil
}

// Active implements the TrustMarkedEntitiesStorageBackend interface
func (store *TrustMarkedEntitiesBadgerStorage) Active(trustMarkID string) ([]string, error) {
	return store.trustMarkedEntities(trustMarkID, StatusActive)
}

// Blocked implements the TrustMarkedEntitiesStorageBackend interface
func (store *TrustMarkedEntitiesBadgerStorage) Blocked(trustMarkID string) ([]string, error) {
	return store.trustMarkedEntities(trustMarkID, StatusBlocked)
}

// Pending implements the TrustMarkedEntitiesStorageBackend interface
func (store *TrustMarkedEntitiesBadgerStorage) Pending(trustMarkID string) ([]string, error) {
	return store.trustMarkedEntities(trustMarkID, StatusPending)
}

func (store *TrustMarkedEntitiesBadgerStorage) key(trustMarkID, entityID string) string {
	return fmt.Sprintf("%s|%s", trustMarkID, entityID)
}

// Load implements the SubordinateStorageBackend interface
func (store *TrustMarkedEntitiesBadgerStorage) Load() error {
	return store.store.Load()
}

// Write implements the TrustMarkedEntitiesStorageBackend interface
func (store *TrustMarkedEntitiesBadgerStorage) write(trustMarkID, entityID string, status Status) error {
	return store.store.Write(store.key(trustMarkID, entityID), status)
}

// Delete implements the TrustMarkedEntitiesStorageBackend interface
func (store *TrustMarkedEntitiesBadgerStorage) Delete(trustMarkID, entityID string) error {
	return store.store.Delete(store.key(trustMarkID, entityID))
}

func (store *TrustMarkedEntitiesBadgerStorage) trustMarkedEntities(
	trustMarkID string, status Status,
) (entityIDs []string, err error) {
	err = store.store.ReadIterator(
		func(k, v []byte) error {
			var id string
			var s Status
			if err = json.Unmarshal(v, &s); err != nil {
				// try legacy storage format
				if e := json.Unmarshal(v, &id); e != nil {
					return err
				}
				s = StatusActive
			} else {
				id = strings.TrimPrefix(string(k), fmt.Sprintf("%s|", trustMarkID))
			}
			if s == status {
				entityIDs = append(entityIDs, id)
			}
			return nil
		},
		trustMarkID,
	)
	return
}

// HasTrustMark implements the TrustMarkedEntitiesStorageBackend interface
func (store *TrustMarkedEntitiesBadgerStorage) HasTrustMark(trustMarkID, entityID string) (bool, error) {
	status, err := store.TrustMarkedStatus(trustMarkID, entityID)
	return status == StatusActive, err
}
