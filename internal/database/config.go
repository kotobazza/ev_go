package database

import "ev/internal/config"

type PostgresConfig struct {
	Host            string
	Port            int
	User            string
	Password        string
	DBName          string
	ConnectionLimit int
}

type RedisConfig struct {
	Host string
	Port int
}

func getDefaultDBConfig() *PostgresConfig {
	return &PostgresConfig{
		Host:            config.Config.Database.Host,
		Port:            config.Config.Database.Port,
		User:            config.Config.Database.User,
		Password:        config.Config.Database.Password,
		DBName:          config.Config.Database.Name,
		ConnectionLimit: config.Config.Database.ConnectionLimit,
	}
}

func getDefaultRedisConfig() *RedisConfig {
	return &RedisConfig{
		Host: config.Config.Redis.Host,
		Port: config.Config.Redis.Port,
	}
}
