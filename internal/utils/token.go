package utils

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"ev/internal/config"
	"ev/internal/database"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

func CreateToken(userID int) (string, error) {

	claims := jwt.MapClaims{
		"user_id": float64(userID),
		"exp":     time.Now().Add(time.Hour * 24).Unix(),
		"iss":     config.Config.JWT.Issuer,
		"nonce":   uuid.New().String(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(config.Config.JWT.Secret))
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %v", err)
	}

	// Сохраняем токен в Redis
	ctx := context.Background()
	redisClient := database.GetIDPRedisConnection()
	key := fmt.Sprintf("token:%d", userID)
	err = redisClient.Set(ctx, key, tokenString, 24*time.Hour).Err()
	if err != nil {
		return "", fmt.Errorf("failed to save token to Redis: %v", err)
	}

	log.Info().Msg("Token created and saved into Redis successfully")

	return tokenString, nil
}

func VerifyToken(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(config.Config.JWT.Secret), nil
	})

	if err != nil {
		log.Error().Msgf("Error parsing token: %v", err)
		return nil, err
	}

	// Проверяем существование токена в Redis
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		userID := int(claims["user_id"].(float64))
		ctx := context.Background()
		redisClient := database.GetIDPRedisConnection()
		key := fmt.Sprintf("token:%d", userID)

		storedToken, err := redisClient.Get(ctx, key).Result()
		if err != nil {
			log.Error().Msgf("Error getting token from Redis: %v", err)
			return nil, errors.New("token not found in Redis")
		}

		if storedToken != tokenString {
			log.Error().Msg("Token has been invalidated")
			return nil, errors.New("token has been invalidated")
		}
	}

	log.Info().Msg("Token verified successfully")

	return token, nil
}

func InvalidateToken(userID int) error {
	ctx := context.Background()
	redisClient := database.GetIDPRedisConnection()
	key := fmt.Sprintf("token:%d", userID)

	err := redisClient.Del(ctx, key).Err()
	if err != nil {
		return fmt.Errorf("failed to invalidate token: %v", err)
	}

	return nil
}

func GetUserIDFromToken(token *jwt.Token) (int, error) {

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		return int(claims["user_id"].(float64)), nil
	}

	return 0, errors.New("user_id not found in token")
}

func GetTempIDFromToken(token *jwt.Token) (string, error) {

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", errors.New("invalid token claims")
	}

	userID, ok := claims["user_id"].(float64)
	if !ok {
		return "", errors.New("user_id not found or invalid type in token")
	}

	nonce, ok := claims["nonce"].(string)
	if !ok {
		return "", errors.New("nonce not found or invalid type in token")
	}

	// Создаем хеш из userID и nonce
	hash := sha256.New()
	hash.Write([]byte(fmt.Sprintf("%d%s", int(userID), nonce)))
	tempID := hex.EncodeToString(hash.Sum(nil))

	return tempID, nil
}
