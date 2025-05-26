package middleware

import (
	"ev/internal/utils"
	"net/http"
	"net/url"
	"time"
)

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("token")
		if err != nil {
			http.Redirect(w, r, "/user/signin?error_msg="+url.QueryEscape("Пожалуйста, войдите в систему"), http.StatusFound)
			return
		}

		token, err := utils.VerifyToken(cookie.Value)
		if err != nil || !token.Valid {
			// Удаляем невалидный cookie
			http.SetCookie(w, &http.Cookie{
				Name:     "token",
				Value:    "",
				Path:     "/",
				Expires:  time.Now().Add(-24 * time.Hour),
				HttpOnly: true,
			})
			http.Redirect(w, r, "/user/signin?error_msg="+url.QueryEscape("Сессия истекла, пожалуйста, войдите снова"), http.StatusFound)
			return
		}

		// Передаём управление следующему обработчику
		next.ServeHTTP(w, r)
	})
}
