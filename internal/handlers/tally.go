package handlers

import (
	"context"
	"encoding/json"
	"ev/internal/config"
	"ev/internal/crypto/bigint"
	"ev/internal/crypto/blind_signature"
	"ev/internal/crypto/merklie"
	"ev/internal/crypto/paillier"
	"ev/internal/crypto/zkp"
	"ev/internal/database"
	"ev/internal/handlers/render"
	"ev/internal/logger"
	"ev/internal/models"
	"fmt"
	"io"
	"net/http"
	"time"
)

type BallotRequestData struct {
	VotingID        int      `json:"voting_id"`
	EncryptedBallot string   `json:"encrypted_ballot"`
	ZKPProofEVec    []string `json:"zkp_proof_e_vec"`
	ZKPProofZVec    []string `json:"zkp_proof_z_vec"`
	ZKPProofAVec    []string `json:"zkp_proof_a_vec"`
	Signature       string   `json:"signature"`
	Label           string   `json:"label"`
	OldLabel        string   `json:"old_label"`
	OldNonce        string   `json:"old_nonce"`
}

type BallotResponseData struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

func addPadding(s string) string {
	for len(s)%4 != 0 {
		s += "="
	}
	return s
}

func SubmitVote(w http.ResponseWriter, r *http.Request) {
	log := logger.GetLogger()
	log.Info().Msg("Requested vote submission")
	w.Header().Set("Content-Type", "application/json")

	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		err = json.NewEncoder(w).Encode(BallotResponseData{
			Success: false,
			Message: "Ошибка при чтении тела запроса",
		})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			log.Error().Err(err).Msg("Error sending response")
		}
		return
	}

	var data BallotRequestData
	err = json.Unmarshal(body, &data)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		err = json.NewEncoder(w).Encode(BallotResponseData{
			Success: false,
			Message: "Ошибка при парсинге JSON данных бюллетеня",
		})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			log.Error().Err(err).Msg("Error sending response")
		}
		return
	}

	ballot, err := bigint.NewBigIntFromBase64(data.EncryptedBallot)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		err = json.NewEncoder(w).Encode(BallotResponseData{
			Success: false,
			Message: "Ошибка при парсинге бюллетеня",
		})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			log.Error().Err(err).Msg("Error sending response")
		}
		return
	}

	votingIDStr := fmt.Sprintf("%d", data.VotingID)
	if ballot.Gt(config.CryptoParams[votingIDStr].RSA.N) {
		w.WriteHeader(http.StatusBadRequest)
		err = json.NewEncoder(w).Encode(BallotResponseData{
			Success: false,
			Message: "Бюллетень слишком большой",
		})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			log.Error().Err(err).Msg("Error sending response")
		}
		return
	}

	db := database.GetCounterPGConnection()
	ctx := context.Background()

	rows, err := db.Query(ctx, "SELECT state FROM votings WHERE id = $1 AND state = 1", data.VotingID)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		err = json.NewEncoder(w).Encode(BallotResponseData{
			Success: false,
			Message: "Ошибка при получении данных о голосовании",
		})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			log.Error().Err(err).Msg("Error sending response")
		}
		return
	}

	defer rows.Close()

	if !rows.Next() {
		w.WriteHeader(http.StatusBadRequest)
		err = json.NewEncoder(w).Encode(BallotResponseData{
			Success: false,
			Message: "Принятие голосов завершено или не началось",
		})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			log.Error().Err(err).Msg("Error sending response")
		}
		return
	}
	label, err := bigint.NewBigIntFromBase64(data.Label)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		err = json.NewEncoder(w).Encode(BallotResponseData{
			Success: false,
			Message: "Ошибка при парсинге метки",
		})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			log.Error().Err(err).Msg("Error sending response")
		}
		return
	}
	bs := blind_signature.BlindSignature{}

	log.Info().Msg("Blind signature verification started")

	signature, err := bigint.NewBigIntFromBase64(data.Signature)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		err = json.NewEncoder(w).Encode(BallotResponseData{
			Success: false,
			Message: "Ошибка при парсинге подписи",
		})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			log.Error().Err(err).Msg("Error sending response")
		}
		return
	}

	var isReVoted bool = false
	var oldLabel *bigint.BigInt = nil

	if !bs.Verify(label, signature, config.CryptoParams[votingIDStr].RSA.E, config.CryptoParams[votingIDStr].RSA.N) {
		if !bs.Verify(label.Mul(bigint.NewBigIntFromUint(config.CryptoParams[votingIDStr].ReVotingMultiplier)), signature, config.CryptoParams[votingIDStr].RSA.E, config.CryptoParams[votingIDStr].RSA.N) {

			w.WriteHeader(http.StatusBadRequest)
			err = json.NewEncoder(w).Encode(BallotResponseData{
				Success: false,
				Message: "Ошибка при верификации подписи",
			})
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				log.Error().Err(err).Msg("Error sending response")
			}
			log.Error().Msg("signature: " + signature.ToBase64())
			log.Error().Msg("ballot: " + label.ToBase64())
			log.Error().Msg("e: " + config.CryptoParams[votingIDStr].RSA.E.ToBase64())
			log.Error().Msg("n: " + config.CryptoParams[votingIDStr].RSA.N.ToBase64())
			return
		} else {
			log.Error().Msg("Re-voted signature verified")
			if data.OldLabel == "" || data.OldNonce == "" {
				w.WriteHeader(http.StatusBadRequest)
				err = json.NewEncoder(w).Encode(BallotResponseData{
					Success: false,
					Message: "Ошибка при парсинге системы меток метки",
				})
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					log.Error().Err(err).Msg("Error sending response")
				}
				return
			}
			oldLabel, err = bigint.NewBigIntFromBase64(addPadding(data.OldLabel))
			if err != nil {
				log.Error().Err(err).Msg("Error parsing old label")
				log.Error().Msg("data.OldLabel: " + data.OldLabel)
				log.Error().Msg("data: " + string(body))

				w.WriteHeader(http.StatusBadRequest)
				err = json.NewEncoder(w).Encode(BallotResponseData{
					Success: false,
					Message: "Ошибка при парсинге старой метки " + err.Error(),
				})

				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					log.Error().Err(err).Msg("Error sending response")
				}
				return
			}
			oldNonce, err := bigint.NewBigIntFromBase64(data.OldNonce)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				err = json.NewEncoder(w).Encode(BallotResponseData{
					Success: false,
					Message: "Ошибка при парсинге старого nonce",
				})
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					log.Error().Err(err).Msg("Error sending response")
				}
				return
			}

			db := database.GetCounterPGConnection()
			ctx := context.Background()

			rows, err := db.Query(ctx,
				"SELECT encrypted_vote FROM encrypted_votes WHERE voting_id = $1 AND label = $2",
				data.VotingID,
				oldLabel.ToBase64(),
			)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				err = json.NewEncoder(w).Encode(BallotResponseData{
					Success: false,
					Message: "Ошибка при проверке бюллетеня",
				})
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					log.Error().Err(err).Msg("Error sending response")
				}
				return
			}

			if !rows.Next() {
				w.WriteHeader(http.StatusBadRequest)
				err = json.NewEncoder(w).Encode(BallotResponseData{
					Success: false,
					Message: "Старый бюллетень не найден",
				})
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					log.Error().Err(err).Msg("Error sending response")
				}
				return
			}
			var encryptedVote string
			err = rows.Scan(&encryptedVote)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				log.Error().Err(err).Msg("Error sending response")
			}
			encryptedVoteBigint, err := bigint.NewBigIntFromBase64(encryptedVote)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				log.Error().Err(err).Msg("Error sending response")
			}

			computedLabel := zkp.ComputeDigest([]*bigint.BigInt{oldNonce, encryptedVoteBigint})
			if computedLabel.Neq(oldLabel) {
				w.WriteHeader(http.StatusBadRequest)
				err = json.NewEncoder(w).Encode(BallotResponseData{
					Success: false,
					Message: "Старый бюллетень не соответствует метке",
				})
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					log.Error().Err(err).Msg("Error sending response")
				}
				return
			}
			log.Info().Msg("Old ballot verified")
			isReVoted = true

		}
	}

	log.Info().Msg("Signature verified")
	log.Info().Msg("ZKP format verification started")

	zkpProofEVec := make([]*bigint.BigInt, len(data.ZKPProofEVec))
	zkpProofZVec := make([]*bigint.BigInt, len(data.ZKPProofZVec))
	zkpProofAVec := make([]*bigint.BigInt, len(data.ZKPProofAVec))

	for i, e := range data.ZKPProofEVec {
		zkpProofEVec[i], err = bigint.NewBigIntFromBase64(e)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			err = json.NewEncoder(w).Encode(BallotResponseData{
				Success: false,
				Message: "Ошибка при парсинге ZKP proof E вектора",
			})
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				log.Error().Err(err).Msg("Error sending response")
			}
			return
		}
	}

	for i, z := range data.ZKPProofZVec {
		zkpProofZVec[i], err = bigint.NewBigIntFromBase64(z)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			err = json.NewEncoder(w).Encode(BallotResponseData{
				Success: false,
				Message: "Ошибка при парсинге ZKP proof Z вектора",
			})
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				log.Error().Err(err).Msg("Error sending response")
			}
			return
		}
	}

	for i, a := range data.ZKPProofAVec {
		zkpProofAVec[i], err = bigint.NewBigIntFromBase64(a)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			err = json.NewEncoder(w).Encode(BallotResponseData{
				Success: false,
				Message: "Ошибка при парсинге ZKP proof A вектора",
			})
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				log.Error().Err(err).Msg("Error sending response")
			}
			return
		}
	}

	validMessages := make([]*bigint.BigInt, len(data.ZKPProofEVec))

	for i := range data.ZKPProofEVec {
		validMessages[i] = bigint.NewBigIntFromInt(int64(2)).Pow(bigint.NewBigIntFromInt(int64(30 * i)))
	}

	zkp := zkp.NewCorrectMessageProof(zkpProofEVec, zkpProofZVec, zkpProofAVec, ballot, validMessages, config.CryptoParams[votingIDStr].Paillier.N, config.CryptoParams[votingIDStr].ChallengeBits)
	err = zkp.Verify()
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		err = json.NewEncoder(w).Encode(BallotResponseData{
			Success: false,
			Message: "Ошибка при верификации ZKP proof: " + err.Error(),
		})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			log.Error().Err(err).Msg("Error sending response")
		}
		return
	}

	log.Info().Msg("ZKP format verified")

	if isReVoted {
		//Посылаем запрос на удаление старого бюллетеня
		log.Info().Msg("Deleting old ballot")
		_, err = db.Exec(ctx,
			"DELETE FROM encrypted_votes WHERE voting_id = $1 AND label = $2",
			data.VotingID,
			oldLabel.ToBase64(),
		)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			log.Error().Err(err).Msg("Error sending response")
		}
		log.Info().Msg("Old ballot deleted")
	}

	_, err = db.Exec(ctx,
		"INSERT INTO encrypted_votes (voting_id, label, encrypted_vote, created_at) VALUES ($1, $2, $3, $4)",
		data.VotingID,
		label.ToBase64(),
		ballot.ToBase64(),
		time.Now(),
	)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		err = json.NewEncoder(w).Encode(BallotResponseData{
			Success: false,
			Message: "Ошибка при добавлении бюллетеня",
		})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			log.Error().Err(err).Msg("Error sending response")
		}
		return
	}

	log.Info().Msg("Ballot added to database")

	err = json.NewEncoder(w).Encode(BallotResponseData{
		Success: true,
		Message: "Бюллетень добавлен в базу данных",
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Error().Err(err).Msg("Error sending response")
	}

	log.Info().Msg("Vote submitted successfully")

}

type ResultsPageData struct {
	Voting *models.Voting
	Result struct {
		ID            int
		VotingID      int
		MerklieRootID int
		ResultedCount map[string]int64
		CryptedResult string
		CreatedAt     time.Time
	}
	MerklieRoot          models.MerklieRoot
	PublicEncryptedVotes []models.PublicEncryptedVote
}

func ShowResultsPage(w http.ResponseWriter, r *http.Request, votingID string) {
	log := logger.GetLogger()
	log.Info().Msg("Showing results page")

	db := database.GetCounterPGConnection()
	ctx := context.Background()

	rows, err := db.Query(ctx, "SELECT * FROM votings WHERE id = $1", votingID)
	if err != nil {
		log.Error().Err(err).Msg("Error getting votings")
		return
	}
	defer rows.Close()

	var voting *models.Voting = nil

	if rows.Next() {
		voting = &models.Voting{}
		err = rows.Scan(&voting.ID, &voting.Name, &voting.Question, &voting.State, &voting.StartTime, &voting.AuditTime, &voting.EndTime)
		if err != nil {
			log.Error().Err(err).Msg("Error scanning votings")
		}
	}
	rows.Close()

	rows, err = db.Query(ctx, "SELECT * FROM voting_options WHERE voting_id = $1", votingID)
	if err != nil {
		log.Error().Err(err).Msg("Error getting voting options")
		return
	}
	defer rows.Close()

	votingOptions := []models.VotingOption{}

	for rows.Next() {
		var votingOption models.VotingOption
		err = rows.Scan(&votingOption.ID, &votingOption.VotingID, &votingOption.OptionIndex, &votingOption.OptionText)
		if err != nil {
			log.Error().Err(err).Msg("Error scanning voting options")
		}
		votingOptions = append(votingOptions, votingOption)
	}

	rows.Close()

	rows, err = db.Query(ctx, "SELECT * FROM results WHERE voting_id = $1", votingID)
	if err != nil {
		log.Error().Err(err).Msg("Error getting results")
		return
	}

	defer rows.Close()

	var result = struct {
		ID            int
		VotingID      int
		MerklieRootID int
		ResultedCount map[string]int64
		CryptedResult string
		CreatedAt     time.Time
	}{
		ResultedCount: make(map[string]int64),
	}

	integeredResult := map[int]int64{}

	var jsonedResultedCount string

	if rows.Next() {
		err = rows.Scan(&result.ID, &result.VotingID, &result.MerklieRootID, &result.CryptedResult, &jsonedResultedCount, &result.CreatedAt)
		if err != nil {
			log.Error().Err(err).Msg("Error scanning results")
		}

		log.Info().Msg("votingOptions: " + fmt.Sprintf("%v", votingOptions))

		log.Info().Msg("jsonedResultedCount: " + jsonedResultedCount)

		err = json.Unmarshal([]byte(jsonedResultedCount), &integeredResult)
		if err != nil {
			log.Error().Err(err).Msg("Error unmarshalling resulted count")
		}

		log.Info().Msg("integeredResult: " + fmt.Sprintf("%v", integeredResult))
	}
	rows.Close()

	for _, option := range votingOptions {

		if val, ok := integeredResult[option.OptionIndex]; ok {
			log.Info().Msg("option: " + fmt.Sprintf("%v", option.OptionIndex))

			result.ResultedCount[option.OptionText] = val
		}
	}

	log.Info().Msg("result.ResultedCount: " + fmt.Sprintf("%v", result.ResultedCount))

	rows, err = db.Query(ctx, "SELECT * FROM merklie_roots WHERE id = $1", result.MerklieRootID)
	if err != nil {
		log.Error().Err(err).Msg("Error getting merklie roots")
		return
	}
	defer rows.Close()

	merklieRoot := models.MerklieRoot{}

	if rows.Next() {
		err = rows.Scan(&merklieRoot.ID, &merklieRoot.VotingID, &merklieRoot.RootValue, &merklieRoot.CreatedAt)
		if err != nil {
			log.Error().Err(err).Msg("Error scanning merklie roots")
		}
	}
	rows.Close()

	rows, err = db.Query(ctx, "SELECT * FROM public_encrypted_votes WHERE voting_id = $1 AND corresponds_to_merklie_root = $2", votingID, result.MerklieRootID)
	if err != nil {
		log.Error().Err(err).Msg("Error getting public encrypted votes")
		return
	}
	defer rows.Close()

	publicEncryptedVotes := []models.PublicEncryptedVote{}

	for rows.Next() {
		var publicEncryptedVote models.PublicEncryptedVote
		err = rows.Scan(&publicEncryptedVote.VotingID, &publicEncryptedVote.Label, &publicEncryptedVote.CorrespondsToMerklieRootID, &publicEncryptedVote.EncryptedVote, &publicEncryptedVote.CreatedAt, &publicEncryptedVote.MovedIntoAt)
		if err != nil {
			log.Error().Err(err).Msg("Error scanning public encrypted votes")
		}
		publicEncryptedVotes = append(publicEncryptedVotes, publicEncryptedVote)
	}

	rows.Close()

	log.Info().Msg("result: " + fmt.Sprintf("%v", result))

	render.RenderTemplate(w, "results", ResultsPageData{
		Voting:               voting,
		Result:               result,
		MerklieRoot:          merklieRoot,
		PublicEncryptedVotes: publicEncryptedVotes,
	})

}

func CalculateVoting(w http.ResponseWriter, r *http.Request, votingID string) {
	log := logger.GetLogger()
	log.Info().Msg("Calculating voting results")
	w.Header().Set("Content-Type", "application/json")

	db := database.GetCounterPGConnection()
	ctx := context.Background()

	rows, err := db.Query(ctx, "SELECT * FROM voting_options WHERE voting_id = $1", votingID)
	if err != nil {
		log.Error().Err(err).Msg("Error getting voting options")
		return
	}
	defer rows.Close()

	votingOptions := []models.VotingOption{}

	for rows.Next() {
		var votingOption models.VotingOption
		err = rows.Scan(&votingOption.ID, &votingOption.VotingID, &votingOption.OptionIndex, &votingOption.OptionText)
		if err != nil {
			log.Error().Err(err).Msg("Error scanning voting options")
		}
		votingOptions = append(votingOptions, votingOption)
	}

	rows.Close()

	rows, err = db.Query(ctx, "SELECT * FROM encrypted_votes WHERE voting_id = $1", votingID)
	if err != nil {
		log.Error().Err(err).Msg("Error getting encrypted votes")
		return
	}
	defer rows.Close()

	encryptedVotes := []models.EncryptedVote{}

	for rows.Next() {
		var encryptedVote models.EncryptedVote
		err = rows.Scan(&encryptedVote.VotingID, &encryptedVote.Label, &encryptedVote.EncryptedVote, &encryptedVote.CreatedAt)
		if err != nil {
			log.Error().Err(err).Msg("Error scanning encrypted votes")
		}
		encryptedVotes = append(encryptedVotes, encryptedVote)
	}

	rows.Close()
	merkleTree := merklie.NewMerkleTree()

	// Добавляем голоса в дерево
	for _, vote := range encryptedVotes {
		merkleTree.AddLeaf(vote.EncryptedVote)
	}

	// Получаем корень дерева
	rootHash := merkleTree.GetRoot()

	cryptoValues := []*bigint.BigInt{}

	for _, vote := range encryptedVotes {
		encryptedVoteBigint, err := bigint.NewBigIntFromBase64(vote.EncryptedVote)
		if err != nil {
			log.Error().Err(err).Msg("Error parsing encrypted vote")
			return
		}
		cryptoValues = append(cryptoValues, encryptedVoteBigint)
	}

	sum := paillier.CountSum(cryptoValues, config.CryptoParams[votingID].Paillier.N)

	decryptedSum, err := paillier.Decrypt(sum, config.CryptoParams[votingID].Paillier.N.Add(bigint.NewBigIntFromInt(1)), config.CryptoParams[votingID].Paillier.Lambda, config.CryptoParams[votingID].Paillier.N)
	if err != nil {
		log.Error().Err(err).Msg("Error decrypting sum")
		return
	}

	binaryString := decryptedSum.ToBinaryString()

	log.Info().Msg("Decrypted sum: " + binaryString)

	chunks := decryptedSum.SplitIntoChunks(uint(config.CryptoParams[votingID].Base))

	numbers := []int64{}

	for _, chunk := range chunks {
		numbers = append(numbers, chunk.Int64())
	}

	log.Info().Msg("Numbers: " + fmt.Sprintf("%v", numbers))

	log.Info().Msg("Root hash: " + rootHash)

	tx, err := db.Begin(ctx)
	if err != nil {
		log.Error().
			Err(err).
			Str("voting_id", votingID).
			Msg("Failed to start transaction")
		return
	}

	currentTime := time.Now()

	// Сохраняем корень в базу данных
	var insertedID int64
	err = tx.QueryRow(ctx, "INSERT INTO merklie_roots (voting_id, root_value, created_at) VALUES ($1, $2, $3) RETURNING id", votingID, rootHash, currentTime).Scan(&insertedID)
	if err != nil {
		tx.Rollback(ctx)
		log.Error().
			Err(err).
			Str("voting_id", votingID).
			Msg("Failed to save merkle root")
		return
	}

	for _, vote := range encryptedVotes {
		_, err = tx.Exec(ctx, "INSERT INTO public_encrypted_votes (voting_id, label, corresponds_to_merklie_root, encrypted_vote, created_at, moved_into_at) VALUES ($1, $2, $3, $4, $5, $6)",
			vote.VotingID, vote.Label, insertedID, vote.EncryptedVote, vote.CreatedAt, currentTime)
		if err != nil {
			tx.Rollback(ctx)
			log.Error().
				Err(err).
				Str("voting_id", votingID).
				Msg("Failed to insert vote into public_encrypted_votes")
			return
		}
	}

	//Вставка результатов голосования в базу данных

	mapResult := make(map[int]int64)

	for _, option := range votingOptions {
		mapResult[option.OptionIndex] = numbers[option.OptionIndex]
	}

	jsonedResult, err := json.Marshal(mapResult)
	if err != nil {
		log.Error().Err(err).Msg("Error marshalling map result")
		return
	}

	_, err = tx.Exec(ctx, "INSERT INTO results (voting_id, corresponds_to_merklie_root, crypted_result, resulted_count, created_at) VALUES ($1, $2, $3, $4, $5)",
		votingID,
		insertedID,
		sum.ToBase64(),
		string(jsonedResult),
		currentTime,
	)
	if err != nil {
		tx.Rollback(ctx)
		log.Error().
			Err(err).
			Str("voting_id", votingID).
			Msg("Failed to insert results into results")
		return
	}

	// Фиксируем транзакцию
	if err = tx.Commit(ctx); err != nil {
		log.Error().
			Err(err).
			Str("voting_id", votingID).
			Msg("Failed to commit transaction")
		tx.Rollback(ctx)
		return
	}

	err = json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Results calculated",
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Error().Err(err).Msg("Error sending response")
	}

	log.Info().Msg("Results calculated")

}
