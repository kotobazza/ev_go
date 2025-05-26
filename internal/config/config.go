package config

import (
	"encoding/json"
	"ev/internal/crypto/bigint"
	"fmt"
	"os"
	"path/filepath"
)

// AppConfig содержит все основные настройки приложения
type AppConfig struct {
	Server struct {
		Host string `json:"host"`
		Port int    `json:"port"`
	} `json:"server"`
	Database struct {
		Host     string `json:"host"`
		Port     int    `json:"port"`
		Name     string `json:"dbname"`
		User     string `json:"user"`
		Password string `json:"password"`
	} `json:"database"`
	Redis struct {
		Host string `json:"host"`
		Port int    `json:"port"`
	} `json:"redis"`
	JWT struct {
		Secret               string `json:"secret"`
		Issuer               string `json:"issuer"`
		TokenValidityMinutes int    `json:"jwtAuthTokenValidityMinutes"`
	} `json:"jwt"`
}

// VotingCryptoConfig содержит криптографические параметры для одного голосования
type VotingCryptoConfig struct {
	VotingID string `json:"voting_id"`
	RSA      struct {
		N *bigint.BigInt `json:"n"`
		E *bigint.BigInt `json:"d"`
		D *bigint.BigInt `json:"e"`
	} `json:"rsa"`
	Paillier struct {
		N      *bigint.BigInt `json:"n"`
		Lambda *bigint.BigInt `json:"lambda"`
	} `json:"paillier"`
	BlockCiphering struct {
		Key []byte `json:"key"`
		IV  []byte `json:"iv"`
	} `json:"block_ciphering"`
}

// CryptoConfig теперь хранит мапу конфигураций голосований
type CryptoConfig map[string]VotingCryptoConfig

var (
	Config       AppConfig
	CryptoParams CryptoConfig
)

// LoadConfigs загружает все конфигурационные файлы
func LoadConfigs(configPath, cryptoPath string) error {
	if err := loadJSONConfig(configPath, &Config); err != nil {
		return fmt.Errorf("ошибка загрузки основного конфига: %w", err)
	}

	if err := loadJSONConfig(cryptoPath, &CryptoParams); err != nil {
		return fmt.Errorf("ошибка загрузки крипто конфига: %w", err)
	}

	return nil
}

// loadJSONConfig загружает JSON файл в указанную структуру
func loadJSONConfig(path string, config interface{}) error {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("ошибка получения абсолютного пути: %w", err)
	}

	file, err := os.ReadFile(absPath)
	if err != nil {
		return fmt.Errorf("ошибка чтения файла: %w", err)
	}

	if err := json.Unmarshal(file, config); err != nil {
		return fmt.Errorf("ошибка парсинга JSON: %w", err)
	}

	return nil
}
