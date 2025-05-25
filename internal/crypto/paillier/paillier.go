package paillier

import (
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"ev/internal/crypto/bigint"
	"strings"
)

// L(x, n) = (x - 1) / n
func L(x, n *bigint.BigInt) *bigint.BigInt {
	res := x.Sub(bigint.NewBigIntFromInt(1))
	return res.Div(n)
}

// LCM использует нашу реализацию из bigint
func LCM(a, b *bigint.BigInt) *bigint.BigInt {
	return bigint.LCM(a, b)
}

// GenerateKeys returns (n, lambda, g = n + 1)
func GeneratePaillierKeys(p, q *bigint.BigInt) (n, lambda, g *bigint.BigInt) {
	n = p.Mul(q)
	p1 := p.Sub(bigint.NewBigIntFromInt(1))
	q1 := q.Sub(bigint.NewBigIntFromInt(1))
	lambda = LCM(p1, q1)
	g = n.Add(bigint.NewBigIntFromInt(1))
	return
}

// Encrypt: c = g^m * r^n mod n^2
func Encrypt(m, r, g, n *bigint.BigInt) *bigint.BigInt {
	nn := n.Mul(n)

	// g^m mod n^2
	gm := g.ModExp(m, nn)
	// r^n mod n^2
	rn := r.ModExp(n, nn)

	// c = (g^m * r^n) mod n^2
	return gm.Mul(rn).Mod(nn)
}

// Decrypt: m = L(c^lambda mod n^2) / L(g^lambda mod n^2) mod n
func Decrypt(c, g, lambda, n *bigint.BigInt) (*bigint.BigInt, error) {
	nn := n.Mul(n)

	// u = c^lambda mod n^2
	u := c.ModExp(lambda, nn)
	l1 := L(u, n)

	// v = g^lambda mod n^2
	v := g.ModExp(lambda, nn)
	l2 := L(v, n)

	// inv = L(g^λ mod n²)^-1 mod n
	inv, err := l2.ModInverse(n)
	if err != nil {
		return nil, errors.New("modular inverse does not exist")
	}

	// m = L(c^λ mod n²) * inv mod n
	return l1.Mul(inv).Mod(n), nil
}

// ComputeDigest returns SHA-512 hash of concatenated BigInts as a new BigInt
func ComputeDigest(values []*bigint.BigInt) *bigint.BigInt {
	h := sha512.New()

	for _, v := range values {
		str := v.ToString() // используем наш метод ToString
		h.Write([]byte(str))
	}

	hash := h.Sum(nil)
	hashHex := hex.EncodeToString(hash)

	// Remove leading 0s and parse as big.Int
	hashHex = strings.TrimLeft(hashHex, "0")
	if hashHex == "" {
		hashHex = "0"
	}

	result, _ := bigint.NewBigIntFromString(hashHex)
	return result
}
