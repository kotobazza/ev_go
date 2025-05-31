package handlers

import (
	"context"
	"encoding/json"
	"ev/internal/config"
	"ev/internal/crypto/bigint"
	"ev/internal/crypto/blind_signature"
	"ev/internal/crypto/zkp"
	"ev/internal/database"
	"ev/internal/logger"
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
}

type BallotResponseData struct {
	Status bool `json:"status"`
}

func SubmitVote(w http.ResponseWriter, r *http.Request) {
	log := logger.GetLogger()
	log.Info().Msg("Requested vote submission")

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusBadRequest)
		log.Error().Msg("Error reading request body")
		return
	}

	var data BallotRequestData
	err = json.Unmarshal(body, &data)
	if err != nil {
		http.Error(w, "Error parsing JSON", http.StatusBadRequest)
		log.Error().Msg("Error parsing JSON")
		return
	}

	ballot, err := bigint.NewBigIntFromBase64(data.EncryptedBallot)
	if err != nil {
		http.Error(w, "Error parsing ballot", http.StatusBadRequest)
		log.Error().Msg("Error parsing ballot")
		return
	}

	votingIDStr := fmt.Sprintf("%d", data.VotingID)
	if ballot.Gt(config.CryptoParams[votingIDStr].RSA.N) {
		http.Error(w, "Blinded ballot is too large", http.StatusBadRequest)
		log.Error().Msg("Blinded ballot is too large")
		return
	}

	label, err := bigint.NewBigIntFromBase64(data.Label)
	if err != nil {
		http.Error(w, "Error parsing label", http.StatusBadRequest)
		log.Error().Msg("Error parsing label")
		return
	}
	bs := blind_signature.BlindSignature{}

	log.Info().Msg("Blind signature verification started")

	signature, err := bigint.NewBigIntFromBase64(data.Signature)
	if err != nil {
		http.Error(w, "Error parsing signature", http.StatusBadRequest)
		log.Error().Msg("Error parsing signature")
		return
	}

	if !bs.Verify(label, signature, config.CryptoParams[votingIDStr].RSA.E, config.CryptoParams[votingIDStr].RSA.N) {
		http.Error(w, "Error verifying signature", http.StatusBadRequest)
		log.Error().Msg("Error verifying signature")
		log.Error().Msg("signature: " + signature.ToBase64())
		log.Error().Msg("ballot: " + label.ToBase64())
		log.Error().Msg("e: " + config.CryptoParams[votingIDStr].RSA.E.ToBase64())
		log.Error().Msg("n: " + config.CryptoParams[votingIDStr].RSA.N.ToBase64())
		return
	}

	log.Info().Msg("Signature verified")
	log.Info().Msg("ZKP format verification started")

	zkpProofEVec := make([]*bigint.BigInt, len(data.ZKPProofEVec))
	zkpProofZVec := make([]*bigint.BigInt, len(data.ZKPProofZVec))
	zkpProofAVec := make([]*bigint.BigInt, len(data.ZKPProofAVec))

	for i, e := range data.ZKPProofEVec {
		zkpProofEVec[i], err = bigint.NewBigIntFromBase64(e)
		if err != nil {
			http.Error(w, "Error parsing ZKP proof E vector", http.StatusBadRequest)
			log.Error().Msg("Error parsing ZKP proof E vector")
			return
		}
	}

	for i, z := range data.ZKPProofZVec {
		zkpProofZVec[i], err = bigint.NewBigIntFromBase64(z)
		if err != nil {
			http.Error(w, "Error parsing ZKP proof Z vector", http.StatusBadRequest)
			log.Error().Msg("Error parsing ZKP proof Z vector")
			return
		}
	}

	for i, a := range data.ZKPProofAVec {
		zkpProofAVec[i], err = bigint.NewBigIntFromBase64(a)
		if err != nil {
			http.Error(w, "Error parsing ZKP proof A vector", http.StatusBadRequest)
			log.Error().Msg("Error parsing ZKP proof A vector")
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
		http.Error(w, "Error verifying ZKP proof: "+err.Error(), http.StatusBadRequest)
		log.Error().Msg("Error verifying ZKP proof: " + err.Error())
		return
	}

	log.Info().Msg("ZKP format verified")

	db := database.GetCounterPGConnection()
	ctx := context.Background()

	_, err = db.Exec(ctx,
		"INSERT INTO encrypted_votes (voting_id, label, encrypted_vote, created_at) VALUES ($1, $2, $3, $4)",
		data.VotingID,
		label.ToBase64(),
		ballot.ToBase64(),
		time.Now(),
	)
	if err != nil {
		http.Error(w, "Ошибка при добавлении бюллетеня", http.StatusInternalServerError)
		log.Error().Msg("Error adding ballot to database")
		return
	}

	log.Info().Msg("Ballot added to database")

	json.NewEncoder(w).Encode(BallotResponseData{Status: true})

	log.Info().Msg("Vote submitted successfully")

}
