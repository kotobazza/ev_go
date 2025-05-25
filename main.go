package main

import (
	"context"
	"ev/internal/config"
	"ev/internal/database"
	"ev/internal/handlers"
	"ev/internal/middleware"
	"fmt"
	"log"
	"net/http"
)

func main() {
	// Загружаем конфигурацию
	if err := config.LoadConfig("config.json"); err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Инициализируем подключения к базам данных
	pgPool := database.GetPGConnection()
	defer database.ClosePGConnection()

	// Инициализируем Redis
	_ = database.GetRedisConnection() // Инициализируем соединение с Redis
	defer database.CloseRedisConnection()

	// Проверяем подключения
	if err := pgPool.Ping(context.Background()); err != nil {
		log.Fatalf("Failed to ping PostgreSQL: %v", err)
	}

	log.Println("Successfully connected to PostgreSQL")
	log.Println("Successfully connected to Redis")

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
	log.Printf("Starting server on %s:%d", config.AppConf.Listeners[0].Address, config.AppConf.Listeners[0].Port)
	err := http.ListenAndServe(
		fmt.Sprintf("%s:%d",
			config.AppConf.Listeners[0].Address,
			config.AppConf.Listeners[0].Port,
		),
		mux,
	)
	if err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
