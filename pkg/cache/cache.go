package cache

import (
	"encoding/base64"
	"time"

	"github.com/patrickmn/go-cache"
)

type Cache interface {
	Get(key string) (any, bool)
	Set(key string, value any, expiration time.Duration)
}

var cacheCache Cache

func init() {
	SetCache(cache.New(time.Hour, 27*time.Minute))
}

func SetCache(cache Cache) {
	cacheCache = cache
}

const (
	KeyEntityStatement = "entity_statement"
	KeyOPMetadata      = "op_metadata"
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
