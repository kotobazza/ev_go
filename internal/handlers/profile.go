package handlers

import (
	"context"
	"net/http"
	"net/url"

	"ev/internal/database"
	"ev/internal/handlers/render"
	"ev/internal/models"

	"github.com/golang-jwt/jwt/v5"
)

type ProfilePageData struct {
	User    User
	Votings []models.Voting
}

func ShowProfilePage(w http.ResponseWriter, r *http.Request) {
	// Получаем токен из запроса
	token := extractAndValidateToken(r)
	if token == nil {
		http.Redirect(w, r, "/user/signin?error_msg="+url.QueryEscape("Пожалуйста, войдите в систему"), http.StatusFound)
		return
	}

	// Получаем ID пользователя из токена
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		http.Error(w, "Недействительный токен", http.StatusUnauthorized)
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
		http.Error(w, "Пользователь не найден", http.StatusNotFound)
		return
	}

	var votings []models.Voting
	rows, err := db.Query(ctx, "SELECT id, name, question FROM Votings")
	if err != nil {
		http.Error(w, "Голосование не найдено", http.StatusNotFound)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var voting models.Voting
		err = rows.Scan(&voting.ID, &voting.Name, &voting.Question)
		if err != nil {
			http.Error(w, "Голосование не найдено", http.StatusNotFound)
			return
		}
		votings = append(votings, voting)
	}

	if err != nil {
		http.Error(w, "Голосование не найдено", http.StatusNotFound)
		return
	}

	// Отображаем шаблон с данными пользователя
	render.RenderTemplate(w, "profile", ProfilePageData{
		User:    user,
		Votings: votings,
	})
}
