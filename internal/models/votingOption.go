package models

type VotingOption struct {
	ID       int    `json:"id"`
	VotingId int    `json:"voting_id"`
	Name     string `json:"name"`
}
