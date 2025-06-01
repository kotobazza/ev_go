package worker

import (
	"context"
	"ev/internal/config"
	merkle "ev/internal/crypto/merklie"
	"ev/internal/database"
	"ev/internal/models"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
)

func RunBackgroundResultPublication(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ReloadResults()
		}
	}
}

func ReloadResults() {
	db := database.GetCounterPGConnection()
	ctx := context.Background()

	rows, err := db.Query(ctx, "SELECT * FROM encrypted_votes")
	if err != nil {
		log.Error().Err(err).Msg("Error reloading results")
	}

	defer rows.Close()

	// Группируем голоса по voting_id
	votesByVotingID := make(map[string][]models.EncryptedVote)

	for rows.Next() {
		var encryptedVote models.EncryptedVote
		err = rows.Scan(&encryptedVote.VotingID, &encryptedVote.Label, &encryptedVote.EncryptedVote, &encryptedVote.CreatedAt)
		if err != nil {
			log.Error().Err(err).Msg("Error scanning encrypted vote")
			continue
		}
		votingIDStr := fmt.Sprintf("%d", encryptedVote.VotingID)
		votesByVotingID[votingIDStr] = append(votesByVotingID[votingIDStr], encryptedVote)
	}

	// Для каждого голосования в конфиге проверяем наличие голосов и строим дерево
	for votingID := range config.CryptoParams {
		votes, hasVotes := votesByVotingID[votingID]
		if !hasVotes {
			log.Info().
				Str("voting_id", votingID).
				Msg("No votes found for voting")
			continue
		}

		// Создаем новое дерево Merkle для текущего голосования
		merkleTree := merkle.NewMerkleTree()

		// Добавляем голоса в дерево
		for _, vote := range votes {
			merkleTree.AddLeaf(vote.EncryptedVote)
		}

		// Получаем корень дерева
		rootHash := merkleTree.GetRoot()

		log.Info().
			Str("voting_id", votingID).
			Str("merkle_root", rootHash).
			Int("total_votes", len(votes)).
			Msg("Merkle tree root calculated")

		// Начинаем транзакцию
		tx, err := db.Begin(ctx)
		if err != nil {
			log.Error().
				Err(err).
				Str("voting_id", votingID).
				Msg("Failed to start transaction")
			continue
		}

		currentTime := time.Now()

		// Сохраняем корень в базу данных
		_, err = tx.Exec(ctx, "INSERT INTO merklie_roots (voting_id, root_value, created_at) VALUES ($1, $2, $3)", votingID, rootHash, currentTime)
		if err != nil {
			tx.Rollback(ctx)
			log.Error().
				Err(err).
				Str("voting_id", votingID).
				Msg("Failed to save merkle root")
			continue
		}

		for _, vote := range votes {
			_, err = tx.Exec(ctx, "INSERT INTO public_encrypted_votes (voting_id, label, encrypted_vote, created_at, moved_into_at) VALUES ($1, $2, $3, $4, $5)",
				vote.VotingID, vote.Label, vote.EncryptedVote, vote.CreatedAt, currentTime)
			if err != nil {
				tx.Rollback(ctx)
				log.Error().
					Err(err).
					Str("voting_id", votingID).
					Msg("Failed to insert vote into public_encrypted_votes")
				continue
			}
		}

		// Фиксируем транзакцию
		if err = tx.Commit(ctx); err != nil {
			log.Error().
				Err(err).
				Str("voting_id", votingID).
				Msg("Failed to commit transaction")
			tx.Rollback(ctx)
			continue
		}
	}
}
