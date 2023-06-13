package cache

import (
	"encoding/base64"
	"time"

	"github.com/patrickmn/go-cache"
)

var cacheCache *cache.Cache

func init() {
	cacheCache = cache.New(time.Hour, 27*time.Minute)
}

const (
	KeyEntityStatement = "entity_statement"
)

func Key(subsystem string, subkey string) string {
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
