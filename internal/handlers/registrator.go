package handlers

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"

	"ev/internal/config"
	"ev/internal/crypto/bigint"
	"ev/internal/crypto/blind_signature"
	"ev/internal/database"
	"ev/internal/handlers/render"
	"ev/internal/logger"
	"ev/internal/models"

	"github.com/golang-jwt/jwt/v5"
)

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

	// Получаем токен из запроса
	token := extractAndValidateToken(r)
	if token == nil {
		log.Error().Msg("Token is nil")
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
	log.Info().Msg("User found")

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
		User:    user,
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

type RequestData struct {
	VotingID      string `json:"voting_id"`
	Ballot        string `json:"ballot"`
	BlindedBallot string `json:"blinded_ballot"`
	R             string `json:"r_base64"`
}

type ResponseData struct {
	Signature string `json:"signature"`
	Success   bool   `json:"success"`
	Message   string `json:"message"`
}

func RegisterVote(w http.ResponseWriter, r *http.Request) {

	log := logger.GetLogger()
	log.Info().Msg("Requested vote registration")

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
	log.Info().Int("user_id", userID).Msg("User ID <временная метка>")
	w.Header().Set("Content-Type", "application/json")
	log.Info().Msg("Token validated")

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusBadRequest)
		log.Error().Msg("Error reading request body")
		return
	}

	var data RequestData
	err = json.Unmarshal(body, &data)
	if err != nil {
		http.Error(w, "Error parsing JSON", http.StatusBadRequest)
		log.Error().Msg("Error parsing JSON")
		log.Error().Msg(string(body))
		log.Error().Err(err).Msg("JSON unmarshal error details")
		return
	}

	blindedBallot, err := bigint.NewBigIntFromBase64(data.BlindedBallot)
	if err != nil {
		http.Error(w, "Error parsing blinded ballot", http.StatusBadRequest)
		log.Error().Msg("Error parsing blinded ballot")
		return
	}

	log.Info().Msg("Blind ballot parsed")

	votingIDStr := data.VotingID

	bs := blind_signature.BlindSignature{}

	signature := bs.SignBlinded(blindedBallot, config.CryptoParams[votingIDStr].RSA.D, config.CryptoParams[votingIDStr].RSA.N)

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(ResponseData{
		Signature: signature.ToBase64(),
		Success:   true,
		Message:   "Vote registered successfully",
	})
	if err != nil {
		http.Error(w, "Error encoding JSON", http.StatusInternalServerError)
		log.Error().Msg("Error sending response")
		return
	}

	log.Info().Msg("Vote registered successfully")
}
