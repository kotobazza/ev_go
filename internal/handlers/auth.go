package handlers

import (
	"context"
	"encoding/json"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"ev/internal/database"
	"ev/internal/handlers/render"
	"ev/internal/logger"
	"ev/internal/utils"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var (
	mu sync.Mutex // Для потокобезопасного доступа

	templates = template.Must(template.ParseGlob("templates/*.html"))
)

type User struct {
	ID    int    `json:"id"`
	Login string `json:"login"`
}

// Отдаёт страницу входа
func ShowLoginPage(w http.ResponseWriter, r *http.Request) {
	log := logger.GetLogger()

	log.Info().
		Msg("Requested login page")

	// Проверяем, есть ли уже валидный токен
	token := extractAndValidateToken(r)
	if token != nil {
		// Если токен валидный, перенаправляем на профиль
		http.Redirect(w, r, "/user/profile", http.StatusFound)
		return
	}

	render.RenderTemplate(w, "login", map[string]interface{}{
		"ErrorMsg": r.URL.Query().Get("error_msg"),
	})

	log.Info().
		Msg("Rendered login page")
}

// Отдаёт страницу регистрации
func ShowSignupPage(w http.ResponseWriter, r *http.Request) {
	log := logger.GetLogger()

	log.Info().
		Msg("Requested signup page")

	// Проверяем, есть ли уже валидный токен
	token := extractAndValidateToken(r)
	if token != nil {
		// Если токен валидный, перенаправляем на профиль
		http.Redirect(w, r, "/user/profile", http.StatusFound)
		return
	}

	render.RenderTemplate(w, "signup", map[string]interface{}{
		"ErrorMsg": r.URL.Query().Get("error_msg"),
	})

	log.Info().
		Msg("Rendered signup page")
}

func Signup(w http.ResponseWriter, r *http.Request) {
	log := logger.GetLogger()

	log.Info().
		Msg("Requested signup")

	log.Info().
		Msg("Form parsing started")

	// Парсим данные формы
	if err := r.ParseForm(); err != nil {
		log.Error().
			Str("error", err.Error()).
			Msg("Failed to parse form")
		http.Redirect(w, r, "/user/signup?error_msg="+url.QueryEscape("Ошибка при обработке формы"), http.StatusFound)
		return
	}

	login := r.PostForm.Get("login")
	password := r.PostForm.Get("password")
	passwordConfirm := r.PostForm.Get("password_confirm")

	log.Info().
		Msg("Form parsed")

	log.Info().
		Msg("Checking credentials")

	if password != passwordConfirm {
		http.Redirect(w, r, "/user/signup?error_msg="+url.QueryEscape("Пароли не совпадают"), http.StatusFound)
		return
	}

	// Хешируем пароль
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Error().
			Str("error", err.Error()).
			Msg("Failed to hash password")
		http.Redirect(w, r, "/user/signup?error_msg="+url.QueryEscape("Ошибка при создании пользователя"), http.StatusFound)
		return
	}

	// Получаем подключение к базе данных
	db := database.GetIDPPGConnection()
	ctx := context.Background()

	// Проверяем, не существует ли уже пользователь с таким логином
	var exists bool
	err = db.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM Users WHERE login = $1)", login).Scan(&exists)
	if err != nil {
		log.Error().
			Str("error", err.Error()).
			Msg("Database error")
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	if exists {
		http.Error(w, "User with this login already exists", http.StatusConflict)
		return
	}

	log.Info().
		Msg("Credentials checked")

	// Создаем нового пользователя
	var user User
	err = db.QueryRow(ctx,
		`INSERT INTO Users (login, password_hash) 
		VALUES ($1, $2) 
		RETURNING id, login`,
		login, string(hashedPassword),
	).Scan(&user.ID, &user.Login)

	if err != nil {
		log.Error().
			Str("error", err.Error()).
			Msg("Failed to create user")
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	log.Info().
		Msg("Created new user")

	log.Info().
		Msg("Creating token")

	// Создаем JWT токен
	token, err := utils.CreateToken(user.ID)
	if err != nil {
		log.Error().
			Str("error", err.Error()).
			Msg("Failed to create token")
		http.Error(w, "Failed to create token", http.StatusInternalServerError)
		return
	}

	// Устанавливаем токен в HTTP-only cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   false, // Только для HTTPS
		SameSite: http.SameSiteStrictMode,
		MaxAge:   86400, // 24 часа
	})

	userJSON, err := json.Marshal(map[string]string{
		"login": user.Login,
		"id":    strconv.Itoa(user.ID),
	})
	if err != nil {
		http.Error(w, "Failed to encode user data", http.StatusInternalServerError)
		return
	}

	encodedValue := url.QueryEscape(string(userJSON))
	log.Info().
		Str("encodedValue", encodedValue).
		Msg("Encoded user data")

	http.SetCookie(w, &http.Cookie{
		Name:     "userData",
		Value:    encodedValue,
		Path:     "/",
		HttpOnly: false,
		Secure:   false, // Только для HTTPS
		SameSite: http.SameSiteStrictMode,
		MaxAge:   86400, // 24 часа
	})

	// Делаем редирект на профиль
	http.Redirect(w, r, "/user/profile", http.StatusFound)

	log.Info().
		Msg("Redirected to profile and token sent to client")
}

func Login(w http.ResponseWriter, r *http.Request) {
	log := logger.GetLogger()

	log.Info().
		Msg("Requested login")

	log.Info().
		Msg("Form parsing started")

	// Парсим данные формы
	if err := r.ParseForm(); err != nil {
		log.Error().
			Str("error", err.Error()).
			Msg("Failed to parse form")
		http.Redirect(w, r, "/user/signin?error_msg="+url.QueryEscape("Ошибка при обработке формы"), http.StatusFound)
		return
	}

	log.Info().
		Msg("Form parsed")

	log.Info().
		Msg("Checking credentials")

	login := r.PostForm.Get("login")
	password := r.PostForm.Get("password")

	// Получаем подключение к базе данных
	db := database.GetIDPPGConnection()
	ctx := context.Background()

	// Ищем пользователя по логину
	var user User
	var hashedPassword string
	err := db.QueryRow(ctx,
		"SELECT id, login, password_hash FROM Users WHERE login = $1",
		login,
	).Scan(&user.ID, &user.Login, &hashedPassword)

	if err != nil {
		log.Error().
			Str("login", login).
			Str("error", err.Error()).
			Msg("Login failed for user")
		http.Redirect(w, r, "/user/signin?error_msg="+url.QueryEscape("Неверный логин или пароль"), http.StatusFound)
		return
	}

	// Проверяем пароль
	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		log.Error().
			Str("login", login).
			Str("error", err.Error()).
			Msg("Password check failed for user")
		http.Redirect(w, r, "/user/signin?error_msg="+url.QueryEscape("Неверный логин или пароль"), http.StatusFound)
		return
	}

	log.Info().
		Msg("Credentials checked")

	log.Info().
		Msg("Creating token")

	// Создаем JWT токен
	token, err := utils.CreateToken(user.ID)
	if err != nil {
		log.Error().
			Str("login", login).
			Str("error", err.Error()).
			Msg("Failed to create token for user")
		http.Error(w, "Failed to create token", http.StatusInternalServerError)
		return
	}

	// Устанавливаем токен в HTTP-only cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   false, // Только для HTTPS
		SameSite: http.SameSiteStrictMode,
		MaxAge:   86400, // 24 часа
	})

	userJSON, err := json.Marshal(map[string]string{
		"login": user.Login,
		"id":    strconv.Itoa(user.ID),
	})
	if err != nil {
		http.Error(w, "Failed to encode user data", http.StatusInternalServerError)
		return
	}

	encodedValue := url.QueryEscape(string(userJSON))
	log.Info().
		Str("encodedValue", encodedValue).
		Msg("Encoded user data")

	http.SetCookie(w, &http.Cookie{
		Name:     "userData",
		Value:    encodedValue,
		Path:     "/",
		HttpOnly: false,
		Secure:   false, // Только для HTTPS
		SameSite: http.SameSiteStrictMode,
		MaxAge:   86400, // 24 часа
	})

	// Делаем редирект на профиль
	http.Redirect(w, r, "/user/profile", http.StatusFound)
	log.Info().
		Msg("Redirected to profile and token sent to client")
}

func Logout(w http.ResponseWriter, r *http.Request) {
	log := logger.GetLogger()

	log.Info().
		Msg("Requested logout")

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

	for _, cookie := range r.Cookies() {
		if strings.HasPrefix(cookie.Name, "oldLabel_") || strings.HasPrefix(cookie.Name, "oldNonce_") {
			http.SetCookie(w, &http.Cookie{
				Name:     cookie.Name,
				Value:    "",
				Path:     "/", // тот же путь, что и у установки
				Expires:  time.Unix(0, 0),
				MaxAge:   -1,
				HttpOnly: true,
			})
		}
	}

	// Перенаправляем на страницу входа
	http.Redirect(w, r, "/user/signin", http.StatusFound)

	log.Info().
		Msg("Redirected to login page and token invalidated")
}

// Извлекает и проверяет токен из запроса
func extractAndValidateToken(r *http.Request) *jwt.Token {
	cookie, err := r.Cookie("token")
	if err != nil {
		return nil
	}

	token, err := utils.VerifyToken(cookie.Value)
	if err != nil || !token.Valid {
		return nil
	}

	return token
}

// GetUserInfo возвращает информацию о пользователе на основе токена
func GetUserInfo(w http.ResponseWriter, r *http.Request) {
	log := logger.GetLogger()

	log.Info().Msg("Requested user info")

	// Получаем и проверяем токен
	token := extractAndValidateToken(r)
	if token == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Получаем ID пользователя из токена
	userID, err := utils.GetUserIDFromToken(token)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get user ID from token")
		http.Error(w, "Failed to get user info", http.StatusInternalServerError)
		return
	}

	// Получаем информацию о пользователе из базы данных
	db := database.GetIDPPGConnection()
	ctx := context.Background()

	var user User
	err = db.QueryRow(ctx,
		"SELECT id, login FROM Users WHERE id = $1",
		userID,
	).Scan(&user.ID, &user.Login)

	if err != nil {
		log.Error().Err(err).Msg("Failed to get user from database")
		http.Error(w, "Failed to get user info", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(user)
}

// GetTempID возвращает временный ID пользователя на основе токена
func GetTempID(w http.ResponseWriter, r *http.Request) {
	log := logger.GetLogger()

	log.Info().Msg("Requested temp ID")

	// Получаем и проверяем токен
	token := extractAndValidateToken(r)
	if token == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Получаем временный ID из токена
	tempID, err := utils.GetTempIDFromToken(token)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get temp ID from token")
		http.Error(w, "Failed to get temp ID", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"temp_id": tempID,
	})
}
