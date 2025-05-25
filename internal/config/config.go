package config

import (
	"encoding/json"
	"os"

	"github.com/redis/go-redis/v9"
)

type Config struct {
	App          AppConfig        `json:"app"`
	Listeners    []ListenerConfig `json:"listeners"`
	DBClients    []DBConfig       `json:"db_clients"`
	RedisClients []RedisConfig    `json:"redis_clients"`
	Log          LogConfig        `json:"log"`
}

type AppConfig struct {
	DocumentRoot      string `json:"document_root"`
	ViewPath          string `json:"view_path"`
	ServerHeaderField string `json:"server_header_field"`
}

type ListenerConfig struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
}

type DBConfig struct {
	Name              string `json:"name"`
	RDBMS             string `json:"rdbms"`
	Host              string `json:"host"`
	Port              int    `json:"port"`
	DBName            string `json:"dbname"`
	User              string `json:"user"`
	Password          string `json:"password"`
	ConnectionTimeout int    `json:"connection_timeout"`
	IdleTime          int    `json:"idle_time"`
	ConnectionLimit   int    `json:"connection_limit"`
}

type RedisConfig struct {
	Name string `json:"name"`
	Host string `json:"host"`
	Port int    `json:"port"`
}

type LogConfig struct {
	LogPath         string `json:"log_path"`
	LogfileBaseName string `json:"logfile_base_name"`
	LogSizeLimit    int    `json:"log_size_limit"`
	LogLevel        string `json:"log_level"`
}

var AppConf Config

func LoadConfig(configPath string) error {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}

	err = json.Unmarshal(data, &AppConf)
	if err != nil {
		return err
	}

	return nil
}

func GetDefaultDBConfig() *DBConfig {
	for _, db := range AppConf.DBClients {
		if db.Name == "default" {
			return &db
		}
	}
	return nil
}

func GetDefaultRedisConfig() *RedisConfig {
	for _, redis := range AppConf.RedisClients {
		if redis.Name == "default" {
			return &redis
		}
	}
	return nil
}

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
