package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"

	"ev/internal/config"
	"ev/internal/database"
	"ev/internal/handlers/render"
	"ev/internal/logger"
	"ev/internal/models"
)

type ProfilePageData struct {
	User    User
	Votings []models.Voting
}

// getUserInfo делает внутренний запрос к /auth/user-info
func getUserInfo(r *http.Request) (*User, error) {
	// Создаем URL для запроса, используя тот же хост
	url := "http://" + config.Config.Server.Host + ":" + strconv.Itoa(config.Config.Server.Port) + "/auth/user-info"

	// Создаем новый запрос к /auth/user-info
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	// Копируем куки из оригинального запроса
	for _, cookie := range r.Cookies() {
		req.AddCookie(cookie)
	}

	// Выполняем запрос
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Проверяем статус ответа
	if resp.StatusCode != http.StatusOK {
		return nil, err
	}

	// Декодируем ответ
	var user User
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, err
	}

	return &user, nil
}

func ShowProfilePage(w http.ResponseWriter, r *http.Request) {
	log := logger.GetLogger()

	log.Info().
		Msg("Requested profile page")

	// Получаем информацию о пользователе через /auth/user-info
	user, err := getUserInfo(r)
	if err != nil {
		http.Redirect(w, r, "/user/signin?error_msg="+url.QueryEscape("Пожалуйста, войдите в систему"), http.StatusFound)
		log.Error().
			Err(err).
			Msg("Error getting user info")
		return
	}

	log.Info().
		Msg("Got user info")

	// Получаем список голосований из базы
	db := database.GetPGConnection()
	ctx := context.Background()

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
		User:    *user,
		Votings: votings,
	})

	log.Info().
		Msg("Rendered profile page")
}

type VotingPageCryptParams struct {
	RsaN          string
	RsaE          string
	PaillierN     string
	ChallengeBits uint
}

type VotingPageData struct {
	User    models.User
	Voting  models.Voting
	Options []models.VotingOption
	Crypto  VotingPageCryptParams
}

func ShowVotingPage(w http.ResponseWriter, r *http.Request, votingID string) {
	log := logger.GetLogger()
	log.Info().Str("voting_id", votingID).Msg("Requested voting page")

	user, err := getUserInfo(r)
	if err != nil {
		http.Redirect(w, r, "/user/signin?error_msg="+url.QueryEscape("Пожалуйста, войдите в систему"), http.StatusFound)
		log.Error().
			Err(err).
			Msg("Error getting user info")
		return
	}
	log.Info().Msg("User info found")

	ctx := r.Context()
	db := database.GetPGConnection()

	// Получаем данные голосования
	var voting models.Voting
	err = db.QueryRow(ctx,
		`SELECT v.id, v.name, v.question
		FROM Votings v
		WHERE v.id = $1`,
		votingID,
	).Scan(
		&voting.ID, &voting.Name, &voting.Question,
	)
	if err != nil {
		http.Error(w, "Голосование не найдено", http.StatusNotFound)
		return
	}
	log.Info().Msg("Voting found")
	// Получаем варианты ответов
	rows, err := db.Query(ctx,
		"SELECT id, option_text FROM VotingOptions WHERE voting_id = $1 ORDER BY id",
		votingID,
	)
	if err != nil {
		http.Error(w, "Ошибка при получении вариантов ответа", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var option models.VotingOption
		if err := rows.Scan(&option.ID, &option.Name); err != nil {
			http.Error(w, "Ошибка при чтении вариантов ответа", http.StatusInternalServerError)
			return
		}
		voting.Options = append(voting.Options, option)
	}
	log.Info().Msg("Voting options found")

	// Проверяем наличие криптографических параметров
	cryptoParams, exists := config.CryptoParams[votingID]
	if !exists {
		log.Error().Str("votingID", votingID).Msg("crypto parameters not found for voting")
		http.Error(w, "Ошибка при получении криптографических параметров", http.StatusInternalServerError)
		return
	}

	// Рендерим шаблон
	render.RenderTemplate(w, "voting", VotingPageData{
		User: models.User{
			ID:           user.ID,
			Login:        user.Login,
			PasswordHash: "",
		},
		Voting:  voting,
		Options: voting.Options,
		Crypto: VotingPageCryptParams{
			RsaN:          cryptoParams.RSA.N.ToBase64(),
			RsaE:          cryptoParams.RSA.E.ToBase64(),
			PaillierN:     cryptoParams.Paillier.N.ToBase64(),
			ChallengeBits: cryptoParams.ChallengeBits,
		},
	})

	log.Info().Msg("Rendered voting page")
}
