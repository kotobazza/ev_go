package models

import "time"

type MerklieRoot struct {
	ID         int
	VotingID   int
	RootValue  string
	CreatedAt  time.Time
	ValidUntil time.Time
}
