package main

import (
	"context"
	"ev/internal/config"
	"ev/internal/database"
	"ev/internal/handlers"
	"ev/internal/logger"
	"ev/internal/middleware"
	"fmt"
	"net/http"
	"os"
)

func main() {
	// Инициализируем логгер
	logger.InitLogger()
	log := logger.GetLogger()

	// Загружаем конфигурацию
	if err := config.LoadConfigs("config.json", "crypto.json"); err != nil {
		log.Fatal().Err(err).Msg("Failed to load config")
		os.Exit(1)
	}

	// Инициализируем подключения к базам данных
	pgPool := database.GetPGConnection()
	defer database.ClosePGConnection()

	// Инициализируем Redis
	_ = database.GetRedisConnection()
	defer database.CloseRedisConnection()

	// Проверяем подключения
	if err := pgPool.Ping(context.Background()); err != nil {
		log.Fatal().Err(err).Msg("Failed to ping PostgreSQL")
		os.Exit(1)
	}

	mux := http.NewServeMux()

	// Статические файлы
	fs := http.FileServer(http.Dir("./static"))
	mux.Handle("/static/", http.StripPrefix("/static/", fs))

	// Страницы аутентификации (GET)
	mux.HandleFunc("/user/signin", handlers.ShowLoginPage)
	mux.HandleFunc("/user/signup", handlers.ShowSignupPage)

	// Защищенные страницы (GET)
	mux.Handle("/user/profile", middleware.AuthMiddleware(http.HandlerFunc(handlers.ShowProfilePage)))

	// Обработчики аутентификации (POST)
	mux.HandleFunc("/user/login/submit", handlers.Login)
	mux.HandleFunc("/user/register/submit", handlers.Signup)
	mux.HandleFunc("/user/logout", handlers.Logout)

	// Запуск сервера
	log.Info().
		Str("host", config.Config.Server.Host).
		Int("port", config.Config.Server.Port).
		Msg("Starting server")

	err := http.ListenAndServe(
		fmt.Sprintf("%s:%d",
			config.Config.Server.Host,
			config.Config.Server.Port,
		),
		mux,
	)
	if err != nil {
		log.Fatal().Err(err).Msg("Server failed to start")
		os.Exit(1)
	}
}
