package database

import (
	"context"
	"ev/internal/config"
	"fmt"
	"sync"

	"github.com/redis/go-redis/v9"
)

var (
	redisClient *redis.Client
	redisOnce   sync.Once
)

func GetRedisConnection() *redis.Client {
	redisOnce.Do(func() {
		redisConfig := config.GetDefaultRedisConfig()
		if redisConfig == nil {
			panic("Default Redis configuration not found")
		}

		redisClient = redis.NewClient(&redis.Options{
			Addr: fmt.Sprintf("%s:%d", redisConfig.Host, redisConfig.Port),
		})

		// Проверка подключения
		ctx := context.Background()
		if err := redisClient.Ping(ctx).Err(); err != nil {
			panic(fmt.Sprintf("Unable to connect to Redis: %v", err))
		}
	})

	return redisClient
}

func CloseRedisConnection() {
	if redisClient != nil {
		redisClient.Close()
	}
}
