package main

import (
	"ev/internal/config"
	"ev/internal/database"
	"ev/internal/handlers"
	"ev/internal/logger"
	"ev/internal/middleware"
	"ev/internal/worker"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	// Инициализируем логгер
	logger.InitLogger()
	log := logger.GetLogger()
	log.Info().Msg("EV - Electronic Voting System")

	// Загружаем конфигурацию
	if err := config.LoadConfigs("config.json", "crypto.json"); err != nil {
		log.Fatal().Err(err).Msg("Failed to load configs")
		os.Exit(1)
	}

	// Инициализируем подключения к базам данных
	_ = database.GetIDPPGConnection()
	defer database.CloseIDPPGConnection()

	_ = database.GetREGPGConnection()
	defer database.CloseREGPGConnection()

	_ = database.GetCounterPGConnection()
	defer database.CloseCounterPGConnection()

	_ = database.GetIDPRedisConnection()
	defer database.CloseIDPRedisConnection()

	_ = database.GetQueueRedisConnection()
	defer database.CloseQueueRedisConnection()

	go worker.RunBackgroundResultPublication(60 * time.Second)
	log.Info().Msg("Background result publication started")

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
	mux.Handle("/auth/user-info", middleware.AuthMiddleware(http.HandlerFunc(handlers.GetUserInfo)))
	mux.Handle("/auth/temp-id", middleware.AuthMiddleware(http.HandlerFunc(handlers.GetTempID)))

	mux.Handle("/tally/calculate-results/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Получаем ID из URL
		votingID := strings.TrimPrefix(r.URL.Path, "/tally/calculate-results/")
		// Передаем управление основному обработчику
		handlers.CalculateVoting(w, r, votingID)
	}))

	mux.Handle("/voting/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Получаем ID из URL
		votingID := strings.TrimPrefix(r.URL.Path, "/voting/")
		// Передаем управление основному обработчику
		handlers.ShowVotingPage(w, r, votingID)
	}))

	mux.Handle("/results/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Получаем ID из URL
		votingID := strings.TrimPrefix(r.URL.Path, "/results/")
		// Передаем управление основному обработчику
		handlers.ShowResultsPage(w, r, votingID)
	}))

	mux.Handle("/admin/votings/delete/", middleware.AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Получаем ID из URL
		votingID := strings.TrimPrefix(r.URL.Path, "/admin/votings/delete/")
		// Передаем управление основному обработчику
		handlers.DeleteVoting(w, r, votingID)

	})))

	mux.Handle("/admin/votings/next-state/", middleware.AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Получаем ID из URL
		votingID := strings.TrimPrefix(r.URL.Path, "/admin/votings/next-state/")
		// Передаем управление основному обработчику
		handlers.NextState(w, r, votingID)

	})))
	mux.Handle("/admin/users/delete/", middleware.AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Получаем ID из URL
		userID := strings.TrimPrefix(r.URL.Path, "/admin/users/delete/")
		// Передаем управление основному обработчику
		handlers.DeleteUser(w, r, userID)

	})))

	mux.Handle("/admin/temp-ids/delete/", middleware.AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Получаем ID из URL
		tempID := strings.TrimPrefix(r.URL.Path, "/admin/temp-ids/delete/")
		// Передаем управление основному обработчику
		handlers.DeleteTempID(w, r, tempID)
	})))

	mux.Handle("/admin/votings/create", middleware.AuthMiddleware(http.HandlerFunc(handlers.AddNewVoting)))

	mux.Handle("/ballot/register", middleware.AuthMiddleware(http.HandlerFunc(handlers.RegisterVote)))
	mux.Handle("/ballot/submit", middleware.AuthMiddleware(http.HandlerFunc(handlers.SubmitVote)))

	// Обработчики аутентификации (POST)
	mux.HandleFunc("/user/login/submit", handlers.Login)
	mux.HandleFunc("/user/register/submit", handlers.Signup)
	mux.HandleFunc("/user/logout", handlers.Logout)

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
				Str("host", config.Config.Server.Host).
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
		log.Info().
			Str("host", config.Config.Server.Host).
			Int("port", config.Config.Server.Port).
			Msg("Starting HTTPS server")
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
		log.Info().
			Str("host", config.Config.Server.Host).
			Int("port", config.Config.Server.Port).
			Msg("Starting HTTP server")
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
