package zkp

import (
	"crypto/rand"
	"crypto/sha256"
	"ev/internal/crypto/bigint"
	"fmt"
)

func randomBigInt(max *bigint.BigInt) *bigint.BigInt {
	bytes := make([]byte, len(max.Bytes()))
	_, err := rand.Read(bytes)
	if err != nil {
		panic(err)
	}
	randInt := bigint.NewBigInt().SetBytes(bytes)
	return randInt.Mod(max)
}

// randomInRange генерирует случайное число в диапазоне [min, max)
func randomInRange(min, max *bigint.BigInt) *bigint.BigInt {
	range_ := max.Sub(min)
	randNum := randomBigInt(range_)
	return randNum.Add(min)
}

func encrypt(N, g, h, m, r *bigint.BigInt) *bigint.BigInt {
	// ElGamal на Paillier: g^m * r^N mod N^2
	NSquared := N.Mul(N)
	gm := g.ModExp(m, NSquared)
	rn := r.ModExp(N, NSquared)

	return gm.Mul(rn).Mod(NSquared)
}

func pow(base, exp, mod *bigint.BigInt) *bigint.BigInt {
	return base.ModExp(exp, mod)
}

func computeDigest(values []*bigint.BigInt) *bigint.BigInt {
	// Отладочный вывод как в C++ версии
	fmt.Println("Go hashing values:")
	for _, val := range values {
		fmt.Println(val.ToString())
	}

	// Создаем SHA-256 хеш
	h := sha256.New()
	for _, val := range values {
		str := val.ToString()
		h.Write([]byte(str))
	}
	hash := h.Sum(nil)

	// Отладочный вывод хеша в hex формате
	fmt.Printf("Go hash hex: %x\n", hash)

	// Преобразуем хеш в BigInt
	result := bigint.NewBigInt().SetBytes(hash)
	fmt.Println("Go final result:", result.ToString())
	return result
}
