package database

import (
	"context"
	"fmt"
	"os"
	"sync"

	"ev/internal/logger"

	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	idpPgPool     *pgxpool.Pool
	regPgPool     *pgxpool.Pool
	counterPgPool *pgxpool.Pool
	idpOnce       sync.Once
	regOnce       sync.Once
	counterOnce   sync.Once
)

func GetIDPPGConnection() *pgxpool.Pool {
	idpOnce.Do(func() {
		dbConfig := getIDPDBConfig()
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

		idpPgPool = pool
	})
	log := logger.GetLogger()
	log.Info().Msg("Successfully created PostgreSQL connection pool")

	if err := idpPgPool.Ping(context.Background()); err != nil {
		log.Fatal().Err(err).Msg("Failed to ping IDP PostgreSQL")
		os.Exit(1)
	}

	return idpPgPool
}

func CloseIDPPGConnection() {
	if idpPgPool != nil {
		idpPgPool.Close()
	}
}

func GetREGPGConnection() *pgxpool.Pool {
	regOnce.Do(func() {
		dbConfig := getREGDBConfig()
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

		regPgPool = pool
	})
	log := logger.GetLogger()
	log.Info().Msg("Successfully created PostgreSQL connection pool")

	if err := regPgPool.Ping(context.Background()); err != nil {
		log.Fatal().Err(err).Msg("Failed to ping REG PostgreSQL")
		os.Exit(1)
	}

	return regPgPool
}

func CloseREGPGConnection() {
	if regPgPool != nil {
		regPgPool.Close()
	}
}

func GetCounterPGConnection() *pgxpool.Pool {
	counterOnce.Do(func() {
		dbConfig := getCounterDBConfig()
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

		counterPgPool = pool
	})
	log := logger.GetLogger()
	log.Info().Msg("Successfully created PostgreSQL connection pool")

	if err := counterPgPool.Ping(context.Background()); err != nil {
		log.Fatal().Err(err).Msg("Failed to ping Counter PostgreSQL")
		os.Exit(1)
	}

	return counterPgPool
}

func CloseCounterPGConnection() {
	if counterPgPool != nil {
		counterPgPool.Close()
	}
}
