package bigint

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

type BigInt struct {
	bn *big.Int
}

// MarshalJSON реализует интерфейс json.Marshaler
func (a *BigInt) MarshalJSON() ([]byte, error) {
	if a == nil || a.bn == nil {
		return []byte("null"), nil
	}
	return json.Marshal(a.ToBase64())
}

// UnmarshalJSON реализует интерфейс json.Unmarshaler
func (a *BigInt) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}

	bi, err := NewBigIntFromBase64(s)
	if err != nil {
		return fmt.Errorf("ошибка преобразования base64 в bigint: %w", err)
	}

	a.bn = bi.bn
	return nil
}

// Конструкторы
func NewBigInt() *BigInt {
	return &BigInt{bn: big.NewInt(0)}
}

func NewBigIntFromUint(n uint64) *BigInt {
	return &BigInt{bn: new(big.Int).SetUint64(n)}
}

func NewBigIntFromString(s string) (*BigInt, error) {
	bi := new(big.Int)
	_, ok := bi.SetString(s, 10)
	if !ok {
		return nil, errors.New("invalid decimal string")
	}
	return &BigInt{bn: bi}, nil
}

func (a *BigInt) ToBase64() string {
	if a == nil || a.bn == nil {
		return ""
	}
	// Преобразуем число в строку
	str := a.bn.Text(10)
	// Кодируем строку в base64
	return base64.StdEncoding.EncodeToString([]byte(str))
}

func NewBigIntFromBase64(b64 string) (*BigInt, error) {
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	// Сначала преобразуем байты в строку
	bi, err := NewBigIntFromString(string(data))
	if err != nil {
		return nil, err
	}
	return bi, nil
}

func NewBigIntFromInt(n int64) *BigInt {
	return &BigInt{bn: big.NewInt(n)}
}

// Копирование
func (a *BigInt) Copy() *BigInt {
	return &BigInt{bn: new(big.Int).Set(a.bn)}
}

// Операции
func (a *BigInt) Add(b *BigInt) *BigInt {
	return &BigInt{bn: new(big.Int).Add(a.bn, b.bn)}
}

func (a *BigInt) Sub(b *BigInt) *BigInt {
	return &BigInt{bn: new(big.Int).Sub(a.bn, b.bn)}
}

func (a *BigInt) Mul(b *BigInt) *BigInt {
	return &BigInt{bn: new(big.Int).Mul(a.bn, b.bn)}
}

func (a *BigInt) Div(b *BigInt) *BigInt {
	return &BigInt{bn: new(big.Int).Div(a.bn, b.bn)}
}

func (a *BigInt) Mod(b *BigInt) *BigInt {
	return &BigInt{bn: new(big.Int).Mod(a.bn, b.bn)}
}

// Сравнение
func (a *BigInt) Cmp(b *BigInt) int {
	return a.bn.Cmp(b.bn)
}

func (a *BigInt) Eq(b *BigInt) bool {
	return a.Cmp(b) == 0
}

func (a *BigInt) Neq(b *BigInt) bool {
	return a.Cmp(b) != 0
}

func (a *BigInt) Lt(b *BigInt) bool {
	return a.Cmp(b) < 0
}

func (a *BigInt) Gt(b *BigInt) bool {
	return a.Cmp(b) > 0
}

func (a *BigInt) Le(b *BigInt) bool {
	return a.Cmp(b) <= 0
}

func (a *BigInt) Ge(b *BigInt) bool {
	return a.Cmp(b) >= 0
}

// Модульная арифметика
func (a *BigInt) ModInverse(mod *BigInt) (*BigInt, error) {
	inv := new(big.Int).ModInverse(a.bn, mod.bn)
	if inv == nil {
		return nil, errors.New("no modular inverse exists")
	}
	return &BigInt{bn: inv}, nil
}

func (a *BigInt) ModExp(exponent, mod *BigInt) *BigInt {
	return &BigInt{bn: new(big.Int).Exp(a.bn, exponent.bn, mod.bn)}
}

func (a *BigInt) Pow(exponent *BigInt) *BigInt {
	return &BigInt{bn: new(big.Int).Exp(a.bn, exponent.bn, nil)}
}

// Строковое представление
func (a *BigInt) ToString() string {
	return a.bn.Text(10)
}

// Вспомогательные функции
func GCD(a, b *BigInt) *BigInt {
	result := new(big.Int).GCD(nil, nil, a.bn, b.bn)
	return &BigInt{bn: result}
}

func LCM(a, b *BigInt) *BigInt {
	gcd := new(big.Int).GCD(nil, nil, a.bn, b.bn)
	if gcd.Sign() == 0 {
		return NewBigInt()
	}
	absA := new(big.Int).Abs(a.bn)
	absB := new(big.Int).Abs(b.bn)
	result := new(big.Int).Div(new(big.Int).Mul(absA, absB), gcd)
	return &BigInt{bn: result}
}

func (a *BigInt) Lsh(n uint) *BigInt {
	return &BigInt{bn: new(big.Int).Lsh(a.bn, n)}
}

func (a *BigInt) ProbablyPrime(n int) bool {
	return a.bn.ProbablyPrime(n)
}

func (a *BigInt) Bytes() []byte {
	return a.bn.Bytes()
}

func (a *BigInt) SetBytes(bytes []byte) *BigInt {
	return &BigInt{bn: new(big.Int).SetBytes(bytes)}
}

func (a *BigInt) Int64() int64 {
	return a.bn.Int64()
}
