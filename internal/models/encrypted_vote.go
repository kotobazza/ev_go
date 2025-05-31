package models

import "time"

type EncryptedVote struct {
	VotingID      int
	Label         string
	EncryptedVote string
	CreatedAt     time.Time
}
