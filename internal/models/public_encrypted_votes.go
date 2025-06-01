package models

import "time"

type PublicEncryptedVote struct {
	VotingID                   int
	CorrespondsToMerklieRootID int
	Label                      string
	EncryptedVote              string
	CreatedAt                  time.Time
	MovedIntoAt                time.Time
}
