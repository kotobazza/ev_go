package models

type User struct {
	ID           int
	Login        string
	PasswordHash string
}
