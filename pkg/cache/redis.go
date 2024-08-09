package cache

import (
	"context"
	"time"

	"github.com/gofiber/fiber/v2/log"
	"github.com/pkg/errors"
	"github.com/redis/go-redis/v9"
)

type redisCache struct {
	client *redis.Client
	ctx    context.Context
}

// Get implements the Cache interface
func (c redisCache) Get(key string) (any, bool) {
	val, err := c.client.Get(c.ctx, key).Result()
	if err != nil {
		if !errors.Is(err, redis.Nil) {
			log.Errorf("error while obtaining from cache: %s", err)
		} else {
		}
		return nil, false
	}
	return val, true
}

// Set implements the Cache interface
func (c redisCache) Set(key string, value any, expiration time.Duration) error {
	return c.client.Set(c.ctx, key, value, expiration).Err()
}

func UseRedisCache(options *redis.Options) error {
	rdb := redis.NewClient(options)
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		return errors.Wrap(err, "could not connect to redis cache")
	}
	SetCache(
		redisCache{
			client: rdb,
			ctx:    context.Background(),
		},
	)
	return nil
}
