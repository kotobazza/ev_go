package handlers

import (
	"context"
	"encoding/json"
	"ev/internal/config"
	"ev/internal/crypto/bigint"
	"ev/internal/crypto/blind_signature"
	"ev/internal/database"
	"ev/internal/handlers/render"
	"ev/internal/logger"
	"ev/internal/models"
	"io"
	"net/http"
	"strconv"
)

type ProfilePageData struct {
	Votings []models.Voting
}

func ShowProfilePage(w http.ResponseWriter, r *http.Request) {
	log := logger.GetLogger()

	log.Info().
		Msg("Requested profile page")

	// Получаем список голосований из базы
	db := database.GetREGPGConnection()
	ctx := context.Background()

	var votings []models.Voting
	rows, err := db.Query(ctx, "SELECT id, name, question FROM votings")
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
	Base          uint
}

type VotingPageData struct {
	Voting  models.Voting
	Options []models.VotingOption
	Crypto  VotingPageCryptParams
}

func ShowVotingPage(w http.ResponseWriter, r *http.Request, votingID string) {
	log := logger.GetLogger()
	log.Info().Str("voting_id", votingID).Msg("Requested voting page")

	ctx := r.Context()
	db := database.GetREGPGConnection()

	// Получаем данные голосования
	var voting models.Voting
	err := db.QueryRow(ctx,
		`SELECT v.id, v.name, v.question
		FROM votings v
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
		"SELECT id, option_index, option_text FROM voting_options WHERE voting_id = $1 ORDER BY id",
		votingID,
	)
	if err != nil {
		http.Error(w, "Ошибка при получении вариантов ответа", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var option models.VotingOption
		if err := rows.Scan(&option.ID, &option.OptionIndex, &option.OptionText); err != nil {
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
		Voting:  voting,
		Options: voting.Options,
		Crypto: VotingPageCryptParams{
			RsaN:          cryptoParams.RSA.N.ToBase64(),
			RsaE:          cryptoParams.RSA.E.ToBase64(),
			PaillierN:     cryptoParams.Paillier.N.ToBase64(),
			ChallengeBits: cryptoParams.ChallengeBits,
			Base:          cryptoParams.Base,
		},
	})

	log.Info().Msg("Rendered voting page")
}

type UserTempID struct {
	TempID string `json:"temp_id"`
}

func getUserTempID(r *http.Request) (string, error) {
	// Создаем URL для запроса, используя тот же хост
	//TODO: тут может быть использование HTTPS, нужно ставить проверку
	url := "http://" + config.Config.Server.Host + ":" + strconv.Itoa(config.Config.Server.Port) + "/auth/temp-id"

	// Создаем новый запрос к /auth/user-info
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	// Копируем куки из оригинального запроса
	for _, cookie := range r.Cookies() {
		req.AddCookie(cookie)
	}

	// Выполняем запрос
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Проверяем статус ответа
	if resp.StatusCode != http.StatusOK {
		return "", err
	}

	// Декодируем ответ
	var tempID UserTempID
	if err := json.NewDecoder(resp.Body).Decode(&tempID); err != nil {
		return "", err
	}

	return tempID.TempID, nil
}

type RequestData struct {
	VotingID      string `json:"voting_id"`
	BlindedBallot string `json:"blinded_ballot"`
}

type ResponseData struct {
	Signature string `json:"signature"`
	Success   bool   `json:"success"`
	Message   string `json:"message"`
}

func RegisterVote(w http.ResponseWriter, r *http.Request) {

	log := logger.GetLogger()
	log.Info().Msg("Requested vote registration")

	tempID, err := getUserTempID(r)
	if err != nil {
		http.Error(w, "Ошибка при получении временного ID", http.StatusInternalServerError)
		return
	}

	log.Info().Msg("User temp ID found in User's request")

	db := database.GetREGPGConnection()
	ctx := context.Background()

	rows, err := db.Query(ctx,
		"SELECT id FROM tempIDs WHERE temp_id = $1",
		tempID,
	)

	if err != nil {
		http.Error(w, "Ошибка при получении временного ID", http.StatusInternalServerError)
		return
	}

	defer rows.Close()

	if rows.Next() {
		log.Error().Msg("Temp ID found in database")
		http.Error(w, "Отказ в подписи бюллетеня: tempID найден в базе", http.StatusForbidden)
		return
	}

	_, err = db.Exec(ctx,
		"INSERT INTO tempIDs (temp_id) VALUES ($1)",
		tempID,
	)
	if err != nil {
		http.Error(w, "Ошибка при добавлении временного ID", http.StatusInternalServerError)
		return
	}

	log.Info().Msg("Temp ID added to database")

	w.Header().Set("Content-Type", "application/json")

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
