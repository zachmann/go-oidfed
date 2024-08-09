package cache

import (
	"encoding"
	"encoding/base64"
	"log"
	"reflect"
	"time"

	"github.com/TwiN/gocache/v2"
	"github.com/pkg/errors"

	"github.com/zachmann/go-oidfed/internal"
)

type Cache interface {
	Get(key string) (any, bool)
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

func (c cacheWrapper) Get(key string) (any, bool) {
	entryV, ok := c.c.Get(key)
	if !ok {
		return nil, false
	}
	entry, ok := entryV.(cacheEntry)
	if !ok {
		internal.Log("invalid cache entry type")
		return nil, false
	}
	t := entry.T
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	v := reflect.New(t).Interface()
	bm, ok := v.(encoding.BinaryUnmarshaler)
	if !ok {
		internal.Logf("cached type '%s' does not implement encoding.BinaryUnmarshaler", entry.T.String())
		return nil, false
	}
	if err := bm.UnmarshalBinary(entry.V); err != nil {
		internal.Log(err)
		return nil, false
	}
	return bm, ok
}

type cacheEntry struct {
	T reflect.Type
	V []byte
}

func (c cacheWrapper) Set(key string, value any, expiration time.Duration) error {
	t := reflect.TypeOf(value)
	v, ok := value.(encoding.BinaryMarshaler)
	if !ok {
		return errors.Errorf("type '%s' does not implement encoding.BinaryMarshaler", t.Name())
	}
	data, err := v.MarshalBinary()
	if err != nil {
		return err
	}
	entry := cacheEntry{
		V: data,
		T: t,
	}
	c.c.SetWithTTL(key, entry, expiration)
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

func Set(key string, value any, duration time.Duration) {
	cacheCache.Set(key, value, duration)
}

func Get(key string) (any, bool) {
	return cacheCache.Get(key)
}
