package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"html/template"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"ev/internal/database"
	"ev/internal/models"
	"ev/internal/utils"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var (
	users         = make(map[string]models.User)
	userIDCounter = 1
	mu            sync.Mutex // Для потокобезопасного доступа

	templates = template.Must(template.ParseGlob("templates/*.html"))
)

type User struct {
	ID           int       `json:"id"`
	Login        string    `json:"login"`
	PasswordHash string    `json:"-"` // Не включаем в JSON
	CreatedAt    time.Time `json:"created_at,omitempty"`
	UpdatedAt    time.Time `json:"updated_at,omitempty"`
}

// Вспомогательная функция рендера шаблона
func renderTemplate(w http.ResponseWriter, tmpl string, data interface{}) {
	err := templates.ExecuteTemplate(w, tmpl+".html", data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// Отдаёт страницу входа
func ShowLoginPage(w http.ResponseWriter, r *http.Request) {
	// Проверяем, есть ли уже валидный токен
	token := extractAndValidateToken(r)
	if token != nil {
		// Если токен валидный, перенаправляем на профиль
		http.Redirect(w, r, "/user/profile", http.StatusFound)
		return
	}

	renderTemplate(w, "login", map[string]interface{}{
		"ErrorMsg": r.URL.Query().Get("error_msg"),
	})
}

// Отдаёт страницу регистрации
func ShowSignupPage(w http.ResponseWriter, r *http.Request) {
	// Проверяем, есть ли уже валидный токен
	token := extractAndValidateToken(r)
	if token != nil {
		// Если токен валидный, перенаправляем на профиль
		http.Redirect(w, r, "/user/profile", http.StatusFound)
		return
	}

	renderTemplate(w, "signup", map[string]interface{}{
		"ErrorMsg": r.URL.Query().Get("error_msg"),
	})
}

func Signup(w http.ResponseWriter, r *http.Request) {
	// Логируем тело запроса
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Error reading body: %v", err)
		http.Error(w, "Can't read body", http.StatusBadRequest)
		return
	}
	// Важно: восстанавливаем тело запроса для последующего использования
	r.Body = io.NopCloser(bytes.NewBuffer(body))

	log.Printf("Received request body: %s", string(body))

	var req struct {
		Login           string `json:"login"`
		Password        string `json:"password"`
		PasswordConfirm string `json:"password_confirm"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("Error decoding JSON: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	log.Printf("Decoded request: login=%s, password_length=%d, password_confirm_length=%d",
		req.Login, len(req.Password), len(req.PasswordConfirm))

	if req.Password != req.PasswordConfirm {
		http.Error(w, "Passwords do not match", http.StatusBadRequest)
		return
	}

	// Хешируем пароль
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	// Получаем подключение к базе данных
	db := database.GetPGConnection()
	ctx := context.Background()

	// Проверяем, не существует ли уже пользователь с таким логином
	var exists bool
	err = db.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM Users WHERE login = $1)", req.Login).Scan(&exists)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	if exists {
		http.Error(w, "User with this login already exists", http.StatusConflict)
		return
	}

	// Создаем нового пользователя
	var user User
	err = db.QueryRow(ctx,
		`INSERT INTO Users (login, password_hash) 
		VALUES ($1, $2) 
		RETURNING id, login`,
		req.Login, string(hashedPassword),
	).Scan(&user.ID, &user.Login)

	if err != nil {
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	// Создаем JWT токен
	token, err := utils.CreateToken(user.ID)
	if err != nil {
		http.Error(w, "Failed to create token", http.StatusInternalServerError)
		return
	}

	// Отправляем токен и редирект
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"token":    token,
		"redirect": "/user/profile",
	})
}

func Login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Login    string `json:"login"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Получаем подключение к базе данных
	db := database.GetPGConnection()
	ctx := context.Background()

	// Ищем пользователя по логину
	var user User
	var hashedPassword string
	err := db.QueryRow(ctx,
		"SELECT id, login, password_hash FROM Users WHERE login = $1",
		req.Login,
	).Scan(&user.ID, &user.Login, &hashedPassword)

	if err != nil {
		log.Printf("Login failed for user %s: %v", req.Login, err)
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Проверяем пароль
	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(req.Password))
	if err != nil {
		log.Printf("Password check failed for user %s: %v", req.Login, err)
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Создаем JWT токен
	token, err := utils.CreateToken(user.ID)
	if err != nil {
		log.Printf("Failed to create token for user %s: %v", req.Login, err)
		http.Error(w, "Failed to create token", http.StatusInternalServerError)
		return
	}

	// Отправляем токен и редирект
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"token":    token,
		"redirect": "/user/profile",
	})
}

func ShowProfilePage(w http.ResponseWriter, r *http.Request) {
	// Получаем токен из запроса
	token := extractAndValidateToken(r)
	if token == nil {
		http.Redirect(w, r, "/user/signin?error_msg=Please+login+first", http.StatusFound)
		return
	}

	// Получаем ID пользователя из токена
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		http.Error(w, "Invalid token claims", http.StatusUnauthorized)
		return
	}

	userID := int(claims["user_id"].(float64))

	// Получаем данные пользователя из базы
	db := database.GetPGConnection()
	ctx := context.Background()

	var user User
	err := db.QueryRow(ctx,
		"SELECT id, login FROM Users WHERE id = $1",
		userID,
	).Scan(&user.ID, &user.Login)

	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Отображаем шаблон с данными пользователя
	renderTemplate(w, "profile", user)
}

func Logout(w http.ResponseWriter, r *http.Request) {
	// Получаем токен
	token := extractAndValidateToken(r)
	if token != nil {
		// Если токен валидный, инвалидируем его
		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			if userID, ok := claims["user_id"].(float64); ok {
				utils.InvalidateToken(int(userID))
			}
		}
	}

	// Удаляем cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    "",
		Path:     "/",
		Expires:  time.Now().Add(-24 * time.Hour),
		HttpOnly: true,
	})

	// Перенаправляем на страницу входа
	http.Redirect(w, r, "/user/signin", http.StatusFound)
}

// Извлекает и проверяет токен из запроса
func extractAndValidateToken(r *http.Request) *jwt.Token {
	// Сначала проверяем заголовок Authorization
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		token, err := utils.VerifyToken(tokenString)
		if err == nil && token.Valid {
			return token
		}
	}

	// Затем проверяем cookie
	cookie, err := r.Cookie("token")
	if err == nil {
		token, err := utils.VerifyToken(cookie.Value)
		if err == nil && token.Valid {
			return token
		}
	}

	return nil
}
