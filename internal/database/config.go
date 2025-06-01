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

func getIDPDBConfig() *PostgresConfig {
	return &PostgresConfig{
		Host:            config.Config.IDPDatabase.Host,
		Port:            config.Config.IDPDatabase.Port,
		User:            config.Config.IDPDatabase.User,
		Password:        config.Config.IDPDatabase.Password,
		DBName:          config.Config.IDPDatabase.Name,
		ConnectionLimit: config.Config.IDPDatabase.ConnectionLimit,
	}
}

func getIDPRedisConfig() *RedisConfig {
	return &RedisConfig{
		Host: config.Config.IDPRedis.Host,
		Port: config.Config.IDPRedis.Port,
	}
}

func getREGDBConfig() *PostgresConfig {
	return &PostgresConfig{
		Host:            config.Config.REGDatabase.Host,
		Port:            config.Config.REGDatabase.Port,
		User:            config.Config.REGDatabase.User,
		Password:        config.Config.REGDatabase.Password,
		DBName:          config.Config.REGDatabase.Name,
		ConnectionLimit: config.Config.REGDatabase.ConnectionLimit,
	}
}

func getCounterDBConfig() *PostgresConfig {
	return &PostgresConfig{
		Host:            config.Config.CounterDatabase.Host,
		Port:            config.Config.CounterDatabase.Port,
		User:            config.Config.CounterDatabase.User,
		Password:        config.Config.CounterDatabase.Password,
		DBName:          config.Config.CounterDatabase.Name,
		ConnectionLimit: config.Config.CounterDatabase.ConnectionLimit,
	}
}

func getQueueRedisConfig() *RedisConfig {
	return &RedisConfig{
		Host: config.Config.QueueRedis.Host,
		Port: config.Config.QueueRedis.Port,
	}
}
