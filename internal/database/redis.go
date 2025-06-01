package database

import (
	"context"
	"fmt"
	"sync"

	"ev/internal/config"
	"ev/internal/logger"

	"github.com/redis/go-redis/v9"
)

var (
	IDPRedisClient   *redis.Client
	IDPRedisOnce     sync.Once
	QueueRedisClient *redis.Client
	QueueRedisOnce   sync.Once
)

func GetIDPRedisConnection() *redis.Client {
	IDPRedisOnce.Do(func() {
		redisConfig := getIDPRedisConfig()
		if redisConfig == nil {
			panic("Default Redis configuration not found")
		}

		IDPRedisClient = redis.NewClient(&redis.Options{
			Addr: fmt.Sprintf("%s:%d", redisConfig.Host, redisConfig.Port),
		})

		// Проверка подключения
		ctx := context.Background()
		if err := IDPRedisClient.Ping(ctx).Err(); err != nil {
			panic(fmt.Sprintf("Unable to connect to Redis: %v", err))
		}
	})

	log := logger.GetLogger()
	log.Info().Msg("Successfully created Redis connection pool")

	return IDPRedisClient
}

func CloseIDPRedisConnection() {
	if IDPRedisClient != nil {
		IDPRedisClient.Close()
	}
}

func GetQueueRedisConnection() *redis.Client {
	QueueRedisOnce.Do(func() {
		redisConfig := getQueueRedisConfig()
		if redisConfig == nil {
			panic("Default Redis configuration not found")
		}

		QueueRedisClient = redis.NewClient(&redis.Options{
			Addr: fmt.Sprintf("%s:%d", redisConfig.Host, redisConfig.Port),
		})

		// Проверка подключения
		ctx := context.Background()
		if err := QueueRedisClient.Ping(ctx).Err(); err != nil {
			panic(fmt.Sprintf("Unable to connect to Redis: %v", err))
		}
	})

	log := logger.GetLogger()
	log.Info().Msg("Successfully created Redis connection pool")

	return QueueRedisClient
}

func CloseQueueRedisConnection() {
	if QueueRedisClient != nil {
		QueueRedisClient.Close()
	}
}

func GetQueueRedisConfig() *RedisConfig {
	return &RedisConfig{
		Host: config.Config.QueueRedis.Host,
		Port: config.Config.QueueRedis.Port,
	}
}
