package models

import "time"

type Result struct {
	ID            int
	VotingID      int
	MerklieRootID int
	ResultedCount string
	CreatedAt     time.Time
}
