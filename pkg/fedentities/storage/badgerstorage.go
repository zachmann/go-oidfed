package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/dgraph-io/badger/v4"

	"github.com/zachmann/go-oidfed/internal/utils"
)

func NewBadgerStorage(path string) (*BadgerStorage, error) {
	storage := &BadgerStorage{Path: path}
	err := storage.Load()
	return storage, err
}

type BadgerStorage struct {
	*badger.DB
	Path   string
	loaded bool
}

func (store *BadgerStorage) SubordinateStorage() *SubordinateBadgerStorage {
	return &SubordinateBadgerStorage{
		store: &BadgerSubStorage{
			db:     store,
			subKey: "subordinates",
		},
	}
}

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

func (store *BadgerStorage) Delete(key string) error {
	return store.Update(
		func(txn *badger.Txn) error {
			return txn.Delete([]byte(key))
		},
	)
}

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

type BadgerSubStorage struct {
	db     *BadgerStorage
	subKey string
}

func (store *BadgerSubStorage) Load() error {
	return store.db.Load()
}
func (store *BadgerSubStorage) key(key string) string {
	return fmt.Sprintf(store.subKey + ":" + key)
}
func (store *BadgerSubStorage) Write(key string, value any) error {
	return store.db.Write(store.key(key), value)
}
func (store *BadgerSubStorage) Delete(key string) error {
	return store.db.Delete(store.key(key))
}
func (store *BadgerSubStorage) Read(key string, target any) (bool, error) {
	return store.db.Read(store.key(key), target)
}
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

type SubordinateBadgerStorage struct {
	store *BadgerSubStorage
}

func (store *SubordinateBadgerStorage) Load() error {
	return store.store.Load()
}
func (store *SubordinateBadgerStorage) Write(entityID string, info SubordinateInfo) error {
	return store.store.Write(entityID, info)
}

func (store *SubordinateBadgerStorage) Delete(entityID string) error {
	return store.store.Delete(entityID)
}

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

func (store *SubordinateBadgerStorage) Q() SubordinateStorageQuery {
	return &BadgerSubordinateStorageQuery{db: store}
}

type BadgerSubordinateStorageQuery struct {
	db      *SubordinateBadgerStorage
	filters []func(info SubordinateInfo) bool
}

func (q BadgerSubordinateStorageQuery) Subordinate(entityID string) (*SubordinateInfo, error) {
	return q.db.Read(entityID)
}

func (q BadgerSubordinateStorageQuery) Subordinates() (infos []SubordinateInfo, err error) {
	err = q.db.store.ReadIterator(
		func(k, v []byte) error {
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

func (q BadgerSubordinateStorageQuery) EntityIDs() (ids []string, err error) {
	err = q.db.store.ReadIterator(
		func(k, v []byte) error {
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

func (q *BadgerSubordinateStorageQuery) AddFilter(filter SubordinateStorageQueryFilter, value any) error {
	q.filters = append(
		q.filters, func(info SubordinateInfo) bool {
			return filter(info, value)
		},
	)
	return nil

}
