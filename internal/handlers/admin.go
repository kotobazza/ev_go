package handlers

import (
	"context"
	"net/http"
	"strings"

	"ev/internal/database"
	"ev/internal/handlers/render"
	"ev/internal/logger"
	"ev/internal/models"
)

type AdminPageData struct {
	Users   []models.User
	Votings []models.Voting
}

func ShowAdminPage(w http.ResponseWriter, r *http.Request) {
	log := logger.GetLogger()
	log.Info().Msg("requested admin page")

	// Получаем данные пользователя из базы
	db := database.GetPGConnection()
	ctx := context.Background()

	var users []models.User
	rows, err := db.Query(ctx, "SELECT id, login, password_hash FROM Users")
	if err != nil {
		http.Error(w, "Запрос таблицы пользователей не удался", http.StatusNotFound)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var user models.User
		err = rows.Scan(&user.ID, &user.Login, &user.PasswordHash)
		if err != nil {
			http.Error(w, "Ошибка переноса пользователя", http.StatusNotFound)
			return
		}
		users = append(users, user)
	}

	var votings []models.Voting
	rows, err = db.Query(ctx, "SELECT id, name, question FROM Votings")
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

	// Отображаем шаблон с данными пользователя
	render.RenderTemplate(w, "admin", AdminPageData{
		Users:   users,
		Votings: votings,
	})
}

func AddUsersFromList(w http.ResponseWriter, r *http.Request) {
}

func AddNewVoting(w http.ResponseWriter, r *http.Request) {
	log := logger.GetLogger()
	log.Info().Msg("requested add new voting")

	// Проверяем метод запроса
	if r.Method != http.MethodPost {
		http.Error(w, "Метод не поддерживается", http.StatusMethodNotAllowed)
		return
	}

	// Получаем данные из формы
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Ошибка при обработке формы", http.StatusBadRequest)
		return
	}

	name := r.FormValue("name")
	description := r.FormValue("description")
	optionsText := r.FormValue("options")

	// Проверяем обязательные поля
	if name == "" || description == "" || optionsText == "" {
		http.Error(w, "Все поля должны быть заполнены", http.StatusBadRequest)
		return
	}

	// Разбиваем опции на отдельные строки
	options := strings.Split(strings.TrimSpace(optionsText), "\n")
	// Убираем пустые строки и пробелы
	var cleanOptions []string
	for _, opt := range options {
		if trimmed := strings.TrimSpace(opt); trimmed != "" {
			cleanOptions = append(cleanOptions, trimmed)
		}
	}

	if len(cleanOptions) < 2 {
		http.Error(w, "Должно быть как минимум 2 варианта ответа", http.StatusBadRequest)
		return
	}

	// Получаем соединение с БД
	db := database.GetPGConnection()
	ctx := context.Background()

	// Начинаем транзакцию
	tx, err := db.Begin(ctx)
	if err != nil {
		http.Error(w, "Ошибка при создании транзакции", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback(ctx)

	// Создаем новое голосование
	var votingID int
	err = tx.QueryRow(ctx,
		"INSERT INTO Votings (name, question) VALUES ($1, $2) RETURNING id",
		name, description,
	).Scan(&votingID)
	if err != nil {
		http.Error(w, "Ошибка при создании голосования", http.StatusInternalServerError)
		return
	}

	// Добавляем варианты ответов
	for _, optionName := range cleanOptions {
		_, err = tx.Exec(ctx,
			"INSERT INTO VotingOptions (voting_id, option_text) VALUES ($1, $2)",
			votingID, optionName,
		)
		if err != nil {
			log.Error().Err(err).Msg("error adding options")
			http.Error(w, "Ошибка при добавлении вариантов ответа", http.StatusInternalServerError)
			return
		}
	}

	// Подтверждаем транзакцию
	err = tx.Commit(ctx)
	if err != nil {
		http.Error(w, "Ошибка при сохранении голосования", http.StatusInternalServerError)
		return
	}

	// Перенаправляем на страницу администратора
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func DeleteUser(w http.ResponseWriter, r *http.Request) {
}

func DeleteVoting(w http.ResponseWriter, r *http.Request) {
}
