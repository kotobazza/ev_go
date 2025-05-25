package utils

import (
	"context"
	"errors"
	"fmt"
	"time"

	"ev/internal/config"
	"ev/internal/database"

	"github.com/golang-jwt/jwt/v5"
)

func CreateToken(userID int) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(time.Hour * 24).Unix(),
		"iss":     config.JwtIssuer,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(config.JwtSecret)
	if err != nil {
		return "", err
	}

	// Сохраняем токен в Redis
	ctx := context.Background()
	redisClient := database.GetRedisConnection()
	key := fmt.Sprintf("token:%d", userID)
	err = redisClient.Set(ctx, key, tokenString, 24*time.Hour).Err()
	if err != nil {
		return "", fmt.Errorf("failed to save token to Redis: %v", err)
	}

	return tokenString, nil
}

func VerifyToken(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return config.JwtSecret, nil
	})

	if err != nil {
		return nil, err
	}

	// Проверяем существование токена в Redis
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		userID := int(claims["user_id"].(float64))
		ctx := context.Background()
		redisClient := database.GetRedisConnection()
		key := fmt.Sprintf("token:%d", userID)

		storedToken, err := redisClient.Get(ctx, key).Result()
		if err != nil {
			return nil, errors.New("token not found in Redis")
		}

		if storedToken != tokenString {
			return nil, errors.New("token has been invalidated")
		}
	}

	return token, nil
}

func InvalidateToken(userID int) error {
	ctx := context.Background()
	redisClient := database.GetRedisConnection()
	key := fmt.Sprintf("token:%d", userID)

	err := redisClient.Del(ctx, key).Err()
	if err != nil {
		return fmt.Errorf("failed to invalidate token: %v", err)
	}

	return nil
}
