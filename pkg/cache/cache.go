package cache

import (
	"encoding/base64"
	"log"
	"time"

	"github.com/TwiN/gocache/v2"
	"github.com/pkg/errors"
	"github.com/vmihailenco/msgpack/v5"

	"github.com/zachmann/go-oidfed/internal"
)

type Cache interface {
	Get(key string, target any) (bool, error)
	Set(key string, value any, expiration time.Duration) error
}

type cacheWrapper struct {
	c *gocache.Cache
}

func newCacheWrapper(defaultExpiration time.Duration) cacheWrapper {
	c := gocache.NewCache().WithDefaultTTL(defaultExpiration)
	if err := c.StartJanitor(); err != nil {
		log.Fatal(err)
	}
	return cacheWrapper{
		c,
	}
}

func (c cacheWrapper) Get(key string, target any) (bool, error) {
	entryV, ok := c.c.Get(key)
	if !ok {
		return false, nil
	}
	entry, ok := entryV.([]byte)
	if !ok {
		internal.Log("invalid cache entry type")
		return false, errors.New("invalid cache entry type")
	}
	return true, msgpack.Unmarshal(entry, target)
}

func (c cacheWrapper) Set(key string, value any, expiration time.Duration) error {
	data, err := msgpack.Marshal(value)
	if err != nil {
		return err
	}
	c.c.SetWithTTL(key, data, expiration)
	return nil
}

var cacheCache Cache

func init() {
	SetCache(newCacheWrapper(time.Hour))
}

func SetCache(cache Cache) {
	cacheCache = cache
}

const (
	KeyEntityStatement     = "entity_statement"
	KeyOPMetadata          = "op_metadata"
	KeyEntityConfiguration = "entity_configuration"
)

func Key(subsystem, subkey string) string {
	return subsystem + ":" + subkey
}

func EntityStmtCacheKey(subID, issID string) string {
	subkey := base64.URLEncoding.EncodeToString([]byte(subID)) + ":" + base64.URLEncoding.EncodeToString([]byte(issID))
	return Key(KeyEntityStatement, subkey)
}

func Set(key string, value any, duration time.Duration) error {
	return cacheCache.Set(key, value, duration)
}

func Get(key string, target any) (bool, error) {
	return cacheCache.Get(key, target)
}
