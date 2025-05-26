package database

import (
	"context"
	"fmt"
	"sync"

	"ev/internal/logger"

	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	pgPool *pgxpool.Pool
	pgOnce sync.Once
)

func GetPGConnection() *pgxpool.Pool {
	pgOnce.Do(func() {
		dbConfig := getDefaultDBConfig()
		if dbConfig == nil {
			panic("Default database configuration not found")
		}

		connString := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable",
			dbConfig.User,
			dbConfig.Password,
			dbConfig.Host,
			dbConfig.Port,
			dbConfig.DBName,
		)

		poolConfig, err := pgxpool.ParseConfig(connString)
		if err != nil {
			panic(fmt.Sprintf("Unable to parse pool config: %v", err))
		}

		poolConfig.MaxConns = int32(dbConfig.ConnectionLimit)

		pool, err := pgxpool.NewWithConfig(context.Background(), poolConfig)
		if err != nil {
			panic(fmt.Sprintf("Unable to create connection pool: %v", err))
		}

		pgPool = pool
	})
	log := logger.GetLogger()
	log.Info().Msg("Successfully created PostgreSQL connection pool")

	return pgPool
}

func ClosePGConnection() {
	if pgPool != nil {
		pgPool.Close()
	}
}
