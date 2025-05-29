package handlers

import (
	"net/http"

	"github.com/golang-jwt/jwt/v5"

	"ev/internal/config"
	"ev/internal/database"
	"ev/internal/handlers/render"
	"ev/internal/logger"
	"ev/internal/models"
)

type VotingPageCryptParams struct {
	RSAPublicN      string
	RSAPublicE      string
	CryptoParametrN string
	CryptoParametrG string
}

type VotingPageData struct {
	User    models.User
	Voting  models.Voting
	Options []models.VotingOption
	Crypto  VotingPageCryptParams
}

func ShowVotingPage(w http.ResponseWriter, r *http.Request, votingID string) {
	log := logger.GetLogger()
	log.Info().Msg("requested voting page")

	// Получаем токен из запроса
	token := extractAndValidateToken(r)
	if token == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	ctx := r.Context()
	db := database.GetPGConnection()

	// Получаем данные пользователя
	claims := token.Claims.(jwt.MapClaims)
	userID := int(claims["user_id"].(float64))

	var user models.User
	err := db.QueryRow(ctx,
		"SELECT id, login FROM Users WHERE id = $1",
		userID,
	).Scan(&user.ID, &user.Login)
	if err != nil {
		http.Error(w, "Пользователь не найден", http.StatusNotFound)
		return
	}
	log.Info().Msg("user found")

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
	log.Info().Msg("voting found")
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
	log.Info().Msg("options found")

	// Проверяем наличие криптографических параметров
	cryptoParams, exists := config.CryptoParams[votingID]
	if !exists {
		log.Error().Str("votingID", votingID).Msg("crypto parameters not found for voting")
		http.Error(w, "Ошибка при получении криптографических параметров", http.StatusInternalServerError)
		return
	}

	// Рендерим шаблон
	render.RenderTemplate(w, "voting", VotingPageData{
		User:    user,
		Voting:  voting,
		Options: voting.Options,
		Crypto: VotingPageCryptParams{
			RSAPublicN:      cryptoParams.RSA.N.ToBase64(),
			RSAPublicE:      cryptoParams.RSA.E.ToBase64(),
			CryptoParametrN: cryptoParams.Paillier.N.ToBase64(),
			CryptoParametrG: cryptoParams.Paillier.Lambda.ToBase64(),
		},
	})

	log.Info().Msg("voting page rendered")
}
