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
	"strings"
)

func main() {
	// Инициализируем логгер
	logger.InitLogger()
	log := logger.GetLogger()
	log.Info().Msg("EV - Electronic Voting System")

	// Загружаем конфигурацию
	if err := config.LoadConfigs("config.json", "crypto.json"); err != nil {
		log.Fatal().Err(err).Msg("Failed to load config")
		os.Exit(1)
	}

	log.Info().Msg("config loaded")

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
	mux.HandleFunc("/admin", handlers.ShowAdminPage)
	mux.HandleFunc("/admin/users/add", handlers.AddUsersFromList)

	// Защищенные страницы (GET)
	mux.Handle("/user/profile", middleware.AuthMiddleware(http.HandlerFunc(handlers.ShowProfilePage)))

	mux.Handle("/voting/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Получаем ID из URL
		votingID := strings.TrimPrefix(r.URL.Path, "/voting/")
		// Передаем управление основному обработчику
		handlers.ShowVotingPage(w, r, votingID)
	}))

	mux.Handle("/admin/votings/create", middleware.AuthMiddleware(http.HandlerFunc(handlers.AddNewVoting)))
	mux.Handle("/admin/users/delete", middleware.AuthMiddleware(http.HandlerFunc(handlers.DeleteUser)))
	mux.Handle("/admin/votings/delete", middleware.AuthMiddleware(http.HandlerFunc(handlers.DeleteVoting)))

	// Обработчики аутентификации (POST)
	mux.HandleFunc("/user/login/submit", handlers.Login)
	mux.HandleFunc("/user/register/submit", handlers.Signup)
	mux.HandleFunc("/user/logout", handlers.Logout)

	// Запуск сервера
	log.Info().
		Str("host", config.Config.Server.Host).
		Int("port", config.Config.Server.Port).
		Msg("Starting server")

	var err error
	if config.Config.Server.TLS.Enabled {
		log.Info().Msg("TLS is enabled")
		go func() {
			httpPort := config.Config.Server.TLS.HTTPPort
			redirectHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				httpsURL := "https://" + r.Host + r.RequestURI
				http.Redirect(w, r, httpsURL, http.StatusMovedPermanently)
			})

			log.Info().
				Int("port", httpPort).
				Msg("Starting HTTP redirect server")

			if err := http.ListenAndServe(
				fmt.Sprintf("%s:%d", config.Config.Server.Host, httpPort),
				redirectHandler,
			); err != nil {
				log.Error().Err(err).Msg("HTTP redirect server failed")
			}
		}()

		// Основной HTTPS сервер
		err := http.ListenAndServeTLS(
			fmt.Sprintf("%s:%d",
				config.Config.Server.Host,
				config.Config.Server.Port,
			),
			config.Config.Server.TLS.CertFile,
			config.Config.Server.TLS.KeyFile,
			mux,
		)
		if err != nil {
			log.Fatal().Err(err).Msg("HTTPS server failed to start")
			os.Exit(1)
		}
	} else {
		log.Info().Msg("TLS is disabled")
		err = http.ListenAndServe(
			fmt.Sprintf("%s:%d",
				config.Config.Server.Host,
				config.Config.Server.Port,
			),
			mux,
		)
	}

	if err != nil {
		log.Fatal().Err(err).Msg("Server failed to start")
		os.Exit(1)
	}
}
