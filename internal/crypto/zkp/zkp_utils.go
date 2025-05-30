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

func ComputeDigest(values []*bigint.BigInt) *bigint.BigInt {
	h := sha256.New()

	for _, val := range values {
		data := val.ToBase64() + "|"
		h.Write([]byte(data))
	}

	hashSum := h.Sum(nil)

	// Преобразуем байты в десятичное число, дополняя каждое число до 3 цифр
	var decimalString string
	for _, b := range hashSum {
		decimalString += fmt.Sprintf("%03d", b)
	}

	result, err := bigint.NewBigIntFromString(decimalString)
	if err != nil {
		panic(err)
	}
	return result
}
