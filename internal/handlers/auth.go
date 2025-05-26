package handlers

import (
	"context"
	"html/template"
	"net/http"
	"net/url"
	"sync"
	"time"

	"ev/internal/database"
	"ev/internal/logger"
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
	log := logger.GetLogger()

	log.Info().
		Str("method", r.Method).
		Str("remote_addr", r.RemoteAddr).
		Msg("Получен запрос на вход")

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
	log := logger.GetLogger()

	log.Info().
		Str("method", r.Method).
		Str("remote_addr", r.RemoteAddr).
		Msg("Получен запрос на регистрацию")

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
	db := database.GetPGConnection()
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

	// Делаем редирект на профиль
	http.Redirect(w, r, "/user/profile", http.StatusFound)
}

func Login(w http.ResponseWriter, r *http.Request) {
	log := logger.GetLogger()

	log.Info().
		Str("method", r.Method).
		Str("remote_addr", r.RemoteAddr).
		Msg("Получен запрос на вход")

	// Парсим данные формы
	if err := r.ParseForm(); err != nil {
		log.Error().
			Str("error", err.Error()).
			Msg("Failed to parse form")
		http.Redirect(w, r, "/user/signin?error_msg="+url.QueryEscape("Ошибка при обработке формы"), http.StatusFound)
		return
	}

	login := r.PostForm.Get("login")
	password := r.PostForm.Get("password")

	// Получаем подключение к базе данных
	db := database.GetPGConnection()
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

	// Делаем редирект на профиль
	http.Redirect(w, r, "/user/profile", http.StatusFound)
}

type ProfilePageData struct {
	User    User
	Votings []models.Voting
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
