package handlers

import (
	"encoding/json"
	"io"
	"net/http"
	"sync"

	"ev/internal/models"
	"ev/internal/utils"

	"golang.org/x/crypto/bcrypt"
)

var (
	users         = make(map[string]models.User)
	userIDCounter = 1
	mu            sync.Mutex // Для потокобезопасного доступа
)

func Signup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Login           string `json:"login"`
		Password        string `json:"password"`
		PasswordConfirm string `json:"password_confirm"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if req.Password != req.PasswordConfirm {
		http.Error(w, "Passwords do not match", http.StatusBadRequest)
		return
	}

	mu.Lock()
	defer mu.Unlock()

	if _, exists := users[req.Login]; exists {
		http.Error(w, "Login already exists", http.StatusConflict)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	user := models.User{
		ID:           userIDCounter,
		Login:        req.Login,
		PasswordHash: string(hashedPassword),
	}
	users[req.Login] = user
	userIDCounter++

	token, err := utils.CreateToken(user.ID)
	if err != nil {
		http.Error(w, "Failed to create token", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"token": token})
}

func Login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Login    string `json:"login"`
		Password string `json:"password"`
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Can't read body", http.StatusBadRequest)
		return
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	mu.Lock()
	user, exists := users[req.Login]
	mu.Unlock()

	if !exists || bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)) != nil {
		http.Error(w, "Invalid login or password", http.StatusUnauthorized)
		return
	}

	token, err := utils.CreateToken(user.ID)
	if err != nil {
		http.Error(w, "Failed to create token", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"token": token})
}
