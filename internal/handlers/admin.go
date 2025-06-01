package handlers

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"ev/internal/database"
	"ev/internal/handlers/render"
	"ev/internal/logger"
	"ev/internal/models"

	"golang.org/x/crypto/bcrypt"
)

const timeFormatStr = "2006-01-02T15:04"

type AdminPageData struct {
	Users          []models.User
	Votings        []models.Voting
	TempIDs        []models.TempID
	EncryptedVotes []models.EncryptedVote
	MerklieRoots   []models.MerklieRoot
}

func ShowAdminPage(w http.ResponseWriter, r *http.Request) {
	log := logger.GetLogger()
	log.Info().Msg("requested admin page")

	// Получаем данные пользователя из базы
	idpDB := database.GetIDPPGConnection()
	idpCtx := context.Background()

	var users []models.User
	rows, err := idpDB.Query(idpCtx, "SELECT id, login, password_hash FROM users")
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

	regDB := database.GetREGPGConnection()
	regCtx := context.Background()

	var votings []models.Voting
	rows, err = regDB.Query(regCtx, "SELECT id, name, question, start_time, audit_time, end_time FROM votings")
	if err != nil {
		http.Error(w, "Запрос таблицы голосований не удался: "+err.Error(), http.StatusNotFound)
		return
	}
	defer rows.Close()

	// Создаем карту для хранения голосований
	votingsMap := make(map[int]*models.Voting)

	for rows.Next() {
		var voting models.Voting
		err = rows.Scan(&voting.ID, &voting.Name, &voting.Question, &voting.StartTime, &voting.AuditTime, &voting.EndTime)
		if err != nil {
			http.Error(w, "Перенос данных из таблицы голосований не удался: "+err.Error(), http.StatusNotFound)
			return
		}
		votingsMap[voting.ID] = &voting
	}

	rows, err = regDB.Query(regCtx, "SELECT id, voting_id, option_index, option_text FROM voting_options")
	if err != nil {
		http.Error(w, "Запрос таблицы опций голосования не удался: "+err.Error(), http.StatusNotFound)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var votingOption models.VotingOption
		err = rows.Scan(&votingOption.ID, &votingOption.VotingID, &votingOption.OptionIndex, &votingOption.OptionText)
		if err != nil {
			http.Error(w, "Перенос данных из таблицы опций голосования не удался: "+err.Error(), http.StatusNotFound)
			return
		}
		if voting, ok := votingsMap[votingOption.VotingID]; ok {
			voting.Options = append(voting.Options, votingOption)
		}
	}

	// Преобразуем карту обратно в слайс
	votings = make([]models.Voting, 0, len(votingsMap))
	for _, v := range votingsMap {
		votings = append(votings, *v)
	}

	var tempIDs []models.TempID
	rows, err = regDB.Query(regCtx, "SELECT id, temp_id FROM tempIDs")
	if err != nil {
		http.Error(w, "Запрос таблицы TempID не удался: "+err.Error(), http.StatusNotFound)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var tempID models.TempID
		err = rows.Scan(&tempID.ID, &tempID.TempID)
		if err != nil {
			http.Error(w, "Перенос данных из таблицы TempID не удался: "+err.Error(), http.StatusNotFound)
			return
		}
		tempIDs = append(tempIDs, tempID)
	}

	counterDB := database.GetCounterPGConnection()
	counterCtx := context.Background()

	var encryptedVotes []models.EncryptedVote
	rows, err = counterDB.Query(counterCtx, "SELECT voting_id, label, encrypted_vote, created_at FROM encrypted_votes")
	if err != nil {
		http.Error(w, "Запрос таблицы EncryptedVote не удался: "+err.Error(), http.StatusNotFound)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var encryptedVote models.EncryptedVote
		err = rows.Scan(&encryptedVote.VotingID, &encryptedVote.Label, &encryptedVote.EncryptedVote, &encryptedVote.CreatedAt)
		if err != nil {
			http.Error(w, "Перенос данных из таблицы EncryptedVote не удался: "+err.Error(), http.StatusNotFound)
			return
		}
		encryptedVotes = append(encryptedVotes, encryptedVote)
	}

	var merklieRoots []models.MerklieRoot
	rows, err = counterDB.Query(counterCtx, "SELECT id, voting_id, root_value, created_at FROM merklie_roots")
	if err != nil {
		http.Error(w, "Запрос таблицы MerklieRoot не удался: "+err.Error(), http.StatusNotFound)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var merklieRoot models.MerklieRoot
		err = rows.Scan(&merklieRoot.ID, &merklieRoot.VotingID, &merklieRoot.RootValue, &merklieRoot.CreatedAt)
		if err != nil {
			http.Error(w, "Перенос данных из таблицы MerklieRoot не удался: "+err.Error(), http.StatusNotFound)
			return
		}
		merklieRoots = append(merklieRoots, merklieRoot)
	}

	// Отображаем шаблон с данными пользователя
	render.RenderTemplate(w, "admin", AdminPageData{
		Users:          users,
		Votings:        votings,
		TempIDs:        tempIDs,
		EncryptedVotes: encryptedVotes,
		MerklieRoots:   merklieRoots,
	})
}

func AddUsersFromList(w http.ResponseWriter, r *http.Request) {
	log := logger.GetLogger()
	log.Info().Msg("requested add users from list")

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

	// Получаем данные из формы
	usersCredentials := r.FormValue("users")

	// Разбиваем строку на отдельные пары логин:пароль
	userPairs := strings.Split(usersCredentials, "\n")

	// Проверяем, что в строке есть хотя бы одна пара
	if len(userPairs) == 0 {
		http.Error(w, "Некорректный формат ввода", http.StatusBadRequest)
		return
	}

	// Создаем карту для хранения пользователей
	userMap := make(map[string]string)

	// Разбираем каждую пару логин:пароль
	for _, pair := range userPairs {
		parts := strings.SplitN(pair, ":", 2)
		if len(parts) == 2 {
			userMap[parts[0]] = parts[1]
		}
	}

	// Получаем соединение с БД
	db := database.GetIDPPGConnection()
	ctx := context.Background()

	// Начинаем транзакцию
	tx, err := db.Begin(ctx)
	if err != nil {
		http.Error(w, "Ошибка при создании транзакции", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback(ctx)

	// Добавляем пользователей
	for login, password := range userMap {
		passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Ошибка при хешировании пароля", http.StatusInternalServerError)
			return
		}
		_, err = tx.Exec(ctx, "INSERT INTO users (login, password_hash) VALUES ($1, $2)", login, passwordHash)
		if err != nil {
			http.Error(w, "Ошибка при добавлении пользователя", http.StatusInternalServerError)
			return
		}
	}

	// Подтверждаем транзакцию
	err = tx.Commit(ctx)
	if err != nil {
		http.Error(w, "Ошибка при сохранении пользователей", http.StatusInternalServerError)
		return
	}

	// Перенаправляем на страницу администратора
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
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
	startTime, _ := time.Parse(timeFormatStr, r.FormValue("start_time"))
	auditTime, _ := time.Parse(timeFormatStr, r.FormValue("audit_time"))
	endTime, _ := time.Parse(timeFormatStr, r.FormValue("end_time"))

	// Проверяем обязательные поля
	if name == "" || description == "" || optionsText == "" || startTime.IsZero() || auditTime.IsZero() || endTime.IsZero() {
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
	db := database.GetREGPGConnection()
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
		"INSERT INTO votings (name, question, start_time, audit_time, end_time) VALUES ($1, $2, $3, $4, $5) RETURNING id",
		name, description, startTime, auditTime, endTime,
	).Scan(&votingID)
	if err != nil {
		http.Error(w, "Ошибка при создании голосования", http.StatusInternalServerError)
		return
	}

	// Добавляем варианты ответов
	for optionIndex, optionName := range cleanOptions {
		_, err = tx.Exec(ctx,
			"INSERT INTO voting_options (voting_id, option_index, option_text) VALUES ($1, $2, $3)",
			votingID, optionIndex, optionName,
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

func DeleteUser(w http.ResponseWriter, r *http.Request, userID string) {
	log := logger.GetLogger()
	log.Info().Msg("requested delete user")

	// Проверяем метод запроса
	if r.Method != http.MethodPost {
		http.Error(w, "Метод не поддерживается", http.StatusMethodNotAllowed)
		return
	}

	// Получаем ID пользователя из формы
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Ошибка при обработке формы", http.StatusBadRequest)
		return
	}

	// Получаем соединение с БД
	db := database.GetIDPPGConnection()
	ctx := context.Background()

	num, err := strconv.Atoi(userID)
	if err != nil {
		log.Error().Err(err).Msg("error converting user ID to int")
		http.Error(w, "Ошибка при конвертации ID пользователя", http.StatusBadRequest)
		return
	}
	// Удаляем пользователя
	_, err = db.Exec(ctx, "DELETE FROM users WHERE id = $1", num)
	if err != nil {
		log.Error().Err(err).Msg("error deleting user")
		http.Error(w, "Ошибка при удалении пользователя", http.StatusInternalServerError)
		return
	}

	// Перенаправляем на страницу администратора
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func DeleteVoting(w http.ResponseWriter, r *http.Request, votingID string) {
	log := logger.GetLogger()
	log.Info().Msg("requested delete voting")

	// Проверяем метод запроса
	if r.Method != http.MethodPost {
		http.Error(w, "Метод не поддерживается", http.StatusMethodNotAllowed)
		return
	}

	// Получаем ID голосования из формы
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Ошибка при обработке формы", http.StatusBadRequest)
		return
	}

	// Получаем соединение с БД
	regDB := database.GetREGPGConnection()
	counterDB := database.GetCounterPGConnection()
	ctx := context.Background()

	// Начинаем транзакцию в БД регистрации
	regTx, err := regDB.Begin(ctx)
	if err != nil {
		http.Error(w, "Ошибка при создании транзакции", http.StatusInternalServerError)
		return
	}
	defer regTx.Rollback(ctx)

	// Удаляем связанные опции голосования
	_, err = regTx.Exec(ctx, "DELETE FROM voting_options WHERE voting_id = $1", votingID)
	if err != nil {
		log.Error().Err(err).Msg("error deleting voting options")
		http.Error(w, "Ошибка при удалении вариантов ответа", http.StatusInternalServerError)
		return
	}

	// Удаляем временные ID, связанные с голосованием
	_, err = regTx.Exec(ctx, "DELETE FROM tempIDs WHERE id IN (SELECT id FROM tempIDs WHERE temp_id LIKE $1 || '%')", votingID)
	if err != nil {
		log.Error().Err(err).Msg("error deleting temp IDs")
		http.Error(w, "Ошибка при удалении временных ID", http.StatusInternalServerError)
		return
	}

	// Удаляем само голосование
	_, err = regTx.Exec(ctx, "DELETE FROM votings WHERE id = $1", votingID)
	if err != nil {
		log.Error().Err(err).Msg("error deleting voting")
		http.Error(w, "Ошибка при удалении голосования", http.StatusInternalServerError)
		return
	}

	// Подтверждаем транзакцию в БД регистрации
	err = regTx.Commit(ctx)
	if err != nil {
		http.Error(w, "Ошибка при сохранении изменений", http.StatusInternalServerError)
		return
	}

	// Удаляем связанные данные из БД подсчета
	// Начинаем транзакцию в БД подсчета
	counterTx, err := counterDB.Begin(ctx)
	if err != nil {
		http.Error(w, "Ошибка при создании транзакции в БД подсчета", http.StatusInternalServerError)
		return
	}
	defer counterTx.Rollback(ctx)

	// Удаляем зашифрованные голоса
	_, err = counterTx.Exec(ctx, "DELETE FROM encrypted_votes WHERE voting_id = $1", votingID)
	if err != nil {
		log.Error().Err(err).Msg("error deleting encrypted votes")
		http.Error(w, "Ошибка при удалении зашифрованных голосов", http.StatusInternalServerError)
		return
	}

	// Удаляем корни Меркла
	_, err = counterTx.Exec(ctx, "DELETE FROM merklie_roots WHERE voting_id = $1", votingID)
	if err != nil {
		log.Error().Err(err).Msg("error deleting merklie roots")
		http.Error(w, "Ошибка при удалении корней Меркла", http.StatusInternalServerError)
		return
	}

	// Подтверждаем транзакцию в БД подсчета
	err = counterTx.Commit(ctx)
	if err != nil {
		http.Error(w, "Ошибка при сохранении изменений в БД подсчета", http.StatusInternalServerError)
		return
	}

	// Перенаправляем на страницу администратора
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func DeleteTempID(w http.ResponseWriter, r *http.Request, tempID string) {
	log := logger.GetLogger()
	log.Info().Msg("requested delete temp ID")

	// Проверяем метод запроса
	if r.Method != http.MethodPost {
		http.Error(w, "Метод не поддерживается", http.StatusMethodNotAllowed)
		return
	}

	// Получаем соединение с БД
	db := database.GetREGPGConnection()
	ctx := context.Background()

	// Удаляем временный ID
	_, err := db.Exec(ctx, "DELETE FROM tempIDs WHERE id = $1", tempID)
	if err != nil {
		log.Error().Err(err).Msg("error deleting temp ID")
		http.Error(w, "Ошибка при удалении временного ID", http.StatusInternalServerError)
		return
	}

	// Перенаправляем на страницу администратора
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}
