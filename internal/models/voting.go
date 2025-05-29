package models

type Voting struct {
	ID       int            `json:"id"`
	Name     string         `json:"name"`
	Question string         `json:"question"`
	Options  []VotingOption `json:"options"`
}
