package models

import "time"

type Voting struct {
	ID        int            `json:"id"`
	Name      string         `json:"name"`
	Question  string         `json:"question"`
	State     int            `json:"state"`
	Options   []VotingOption `json:"options"`
	StartTime time.Time      `json:"start_time"`
	AuditTime time.Time      `json:"audit_time"`
	EndTime   time.Time      `json:"end_time"`
}
