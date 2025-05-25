package config

import (
	"github.com/redis/go-redis/v9"
)

var (
	JwtSecret   = []byte("your_jwt_secret")
	JwtIssuer   = "your_app_name"
	RedisClient *redis.Client
)

func InitRedis() {
	RedisClient = redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})
}
