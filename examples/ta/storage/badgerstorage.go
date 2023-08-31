package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/dgraph-io/badger/v4"

	"github.com/zachmann/go-oidcfed/examples/ta/config"
	"github.com/zachmann/go-oidcfed/internal/utils"
)

type BadgerStorage struct {
	storage   *badger.DB
	entityIDs map[string][]string
	mutex     sync.RWMutex
}

func NewBadgerStorage() *BadgerStorage {
	return &BadgerStorage{
		entityIDs: make(map[string][]string),
	}
}

func (store *BadgerStorage) Load() error {
	db, err := badger.Open(badger.DefaultOptions(config.Get().DataLocation))
	if err != nil {
		log.Fatal(err)
	}
	store.storage = db

	store.mutex.Lock()
	defer store.mutex.Unlock()

	if err = db.View(
		func(txn *badger.Txn) error {
			opts := badger.DefaultIteratorOptions
			opts.PrefetchSize = 10
			it := txn.NewIterator(opts)
			defer it.Close()
			for it.Rewind(); it.Valid(); it.Next() {
				item := it.Item()
				if err = item.Value(
					func(v []byte) error {
						var info SubordinateInfo
						if err = json.Unmarshal(v, &info); err != nil {
							return err
						}
						store.entityIDs[info.EntityType] = append(store.entityIDs[info.EntityType], info.EntityID)
						if info.EntityType != "" {
							store.entityIDs[""] = append(store.entityIDs[""], info.EntityID)
						}
						return nil
					},
				); err != nil {
					return err
				}
			}
			return nil
		},
	); err != nil {
		log.Fatal(err.Error())
	}

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
	return nil
}

func addToSliceIfNotExists[C comparable](item C, slice []C) []C {
	if !utils.SliceContains(item, slice) {
		slice = append(slice, item)
	}
	return slice
}

func (store *BadgerStorage) Write(entityID string, info SubordinateInfo) error {

	data, err := json.Marshal(info)
	if err != nil {
		return err
	}
	err = store.storage.Update(
		func(txn *badger.Txn) error {
			if err = txn.Set([]byte(entityID), data); err != nil {
				return err
			}
			store.mutex.Lock()
			defer store.mutex.Unlock()
			store.entityIDs[info.EntityType] = addToSliceIfNotExists(entityID, store.entityIDs[info.EntityType])
			if info.EntityType != "" {
				store.entityIDs[""] = addToSliceIfNotExists(entityID, store.entityIDs[""])
			}
			return nil
		},
	)
	return err
}

func (store *BadgerStorage) Read(entityID string) (info SubordinateInfo, err error) {
	err = store.storage.View(
		func(txn *badger.Txn) error {
			item, err := txn.Get([]byte(entityID))
			if errors.Is(err, badger.ErrKeyNotFound) {
				return errors.New(fmt.Sprintf("'%s' not found", entityID))
			}

			return item.Value(
				func(val []byte) error {
					return json.Unmarshal(val, &info)
				},
			)
		},
	)
	return
}
func (store *BadgerStorage) ListSubordinates(entityType string) (entities []string, err error) {
	store.mutex.RLock()
	defer store.mutex.RUnlock()
	return store.entityIDs[entityType], nil
}
