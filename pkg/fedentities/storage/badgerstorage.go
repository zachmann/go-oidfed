package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/dgraph-io/badger/v4"

	"github.com/zachmann/go-oidfed/internal/utils"
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

// ReadIterator uses the passed iterator function do iterate over all the key,=-value-pairs in this sub storage
func (store *BadgerSubStorage) ReadIterator(do func(k, v []byte) error) error {
	return store.db.View(
		func(txn *badger.Txn) error {
			it := txn.NewIterator(badger.DefaultIteratorOptions)
			defer it.Close()
			prefix := []byte(store.subKey + ":")
			for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
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

// Q returns a SubordinateStorageQuery
func (store *SubordinateBadgerStorage) Q() SubordinateStorageQuery {
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
