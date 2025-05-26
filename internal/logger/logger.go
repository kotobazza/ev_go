package logger

import (
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func InitLogger() {
	// Настраиваем красивый вывод для разработки
	output := zerolog.ConsoleWriter{
		Out:        os.Stdout,
		TimeFormat: time.RFC3339,
	}

	// Устанавливаем глобальный логгер
	log.Logger = zerolog.New(output).
		With().
		Timestamp().
		Caller().
		Logger()

	zerolog.SetGlobalLevel(zerolog.InfoLevel)
}

// GetLogger возвращает настроенный логгер
func GetLogger() *zerolog.Logger {
	return &log.Logger
}
