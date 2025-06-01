package models

type Result struct {
	ID            int
	VotingID      int
	MerkleRoot    string
	ResultedCount int
	CreatedAt     string
	ZkpProof      string
}
