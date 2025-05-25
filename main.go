package main

import (
	"ev/internal/handlers"
	"ev/internal/middleware"
	"log"
	"net/http"
)

func main() {
	mux := http.NewServeMux()

	// Открытые маршруты
	mux.HandleFunc("/signup", handlers.Signup)
	mux.HandleFunc("/login", handlers.Login)

	// Пример защищённого маршрута
	mux.Handle("/profile", middleware.AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("This is a protected profile page"))
	})))

	// Запускаем сервер
	log.Println("Starting server on :8080")
	err := http.ListenAndServe(":8080", mux)
	if err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
