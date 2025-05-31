package handlers

import (
	"encoding/json"
	"ev/internal/config"
	"ev/internal/crypto/bigint"
	"ev/internal/crypto/blind_signature"
	"ev/internal/logger"
	"io"
	"net/http"
	"strconv"
)

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

	tempID, err := getUserTempID(r)
	if err != nil {
		http.Error(w, "Ошибка при получении временного ID", http.StatusInternalServerError)
		return
	}

	log.Info().Str("temp_id", tempID).Msg("User temp ID found <временная метка>")

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
