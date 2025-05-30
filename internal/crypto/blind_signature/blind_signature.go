package blind_signature

import (
	"crypto/rand"
	"errors"
	"ev/internal/crypto/bigint"
)

type RSAKeyPair struct {
	PublicKey  PublicKey
	PrivateKey PrivateKey
}

type PublicKey struct {
	E *bigint.BigInt
	N *bigint.BigInt
}

type PrivateKey struct {
	D *bigint.BigInt
	N *bigint.BigInt
}

func NewRSAKeyPair(bits int) (*RSAKeyPair, error) {
	p, err := generatePrime(bits)
	if err != nil {
		return nil, err
	}
	q, err := generatePrime(bits)
	if err != nil {
		return nil, err
	}
	for p.Eq(q) {
		q, err = generatePrime(bits)
		if err != nil {
			return nil, err
		}
	}

	n := p.Mul(q)
	phi := p.Sub(bigint.NewBigIntFromInt(1)).Mul(q.Sub(bigint.NewBigIntFromInt(1)))

	e := bigint.NewBigIntFromInt(65537)
	one := bigint.NewBigIntFromInt(1)
	for bigint.GCD(e, phi).Eq(one) == false {
		e = e.Add(bigint.NewBigIntFromInt(2))
	}

	d, err := e.ModInverse(phi)
	if err != nil {
		return nil, errors.New("no modular inverse for e mod phi")
	}

	return &RSAKeyPair{
		PublicKey:  PublicKey{E: e, N: n},
		PrivateKey: PrivateKey{D: d, N: n},
	}, nil
}

func generatePrime(bits int) (*bigint.BigInt, error) {
	bytes := make([]byte, bits/8)
	for {
		_, err := rand.Read(bytes)
		if err != nil {
			return nil, err
		}
		// Устанавливаем старший бит в 1 для обеспечения нужной длины
		bytes[0] |= 0x80
		// Устанавливаем младший бит в 1 для обеспечения нечётности
		bytes[len(bytes)-1] |= 0x01

		p := bigint.NewBigInt().SetBytes(bytes)
		if p.ProbablyPrime(20) {
			return p, nil
		}
	}
}

func randomBigInt(min, max *bigint.BigInt) (*bigint.BigInt, error) {
	diff := max.Sub(min)
	bytes := make([]byte, len(diff.Bytes()))
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, err
	}
	randInt := bigint.NewBigInt().SetBytes(bytes)
	return randInt.Mod(diff).Add(min), nil
}

// --------------------- Blind Signature -----------------------

type BlindSignature struct{}

func (bs BlindSignature) SignBlinded(blinded, d, n *bigint.BigInt) *bigint.BigInt {
	return blinded.ModExp(d, n)
}

func (bs BlindSignature) Blind(message, e, n *bigint.BigInt) (*bigint.BigInt, *bigint.BigInt, error) {
	var r *bigint.BigInt
	var err error
	for {
		r, err = randomBigInt(bigint.NewBigIntFromInt(2), n.Sub(bigint.NewBigIntFromInt(1)))
		if err != nil {
			return nil, nil, err
		}
		if bigint.GCD(r, n).Eq(bigint.NewBigIntFromInt(1)) {
			break
		}
	}

	rPowE := r.ModExp(e, n)
	blinded := message.Mul(rPowE).Mod(n)
	return blinded, r, nil
}

func (bs BlindSignature) Unblind(blindedSig, r, n *bigint.BigInt) *bigint.BigInt {
	rInv, _ := r.ModInverse(n)
	return blindedSig.Mul(rInv).Mod(n)
}

func (bs BlindSignature) Verify(message, signature, e, n *bigint.BigInt) bool {
	expected := signature.ModExp(e, n)
	return expected.Eq(message)
}

func MessageToBigInt(message string) *bigint.BigInt {
	result := bigint.NewBigIntFromInt(0)
	for _, b := range []byte(message) {
		result = result.Mul(bigint.NewBigIntFromInt(256))
		result = result.Add(bigint.NewBigIntFromInt(int64(b)))
	}
	return result
}

func BigIntToMessage(bi *bigint.BigInt) string {
	bytes := []byte{}
	tmp := bi.Copy()
	zero := bigint.NewBigIntFromInt(0)
	base := bigint.NewBigIntFromInt(256)

	for tmp.Gt(zero) {
		mod := tmp.Mod(base)
		tmp = tmp.Div(base)
		bytes = append([]byte{byte(mod.Int64())}, bytes...)
	}
	return string(bytes)
}

// --------------------- Пример -----------------------

// func main() {
// 	keypair, err := NewRSAKeyPair(512)
// 	if err != nil {
// 		panic(err)
// 	}

// 	message := "hello world"
// 	m := MessageToBigInt(message)

// 	bs := BlindSignature{}
// 	blinded, r, err := bs.Blind(m, keypair.PublicKey.E, keypair.PublicKey.N)
// 	if err != nil {
// 		panic(err)
// 	}

// 	signed := bs.SignBlinded(blinded, keypair.PrivateKey.D, keypair.PrivateKey.N)
// 	unblinded := bs.Unblind(signed, r, keypair.PublicKey.N)

// 	valid := bs.Verify(m, unblinded, keypair.PublicKey.E, keypair.PublicKey.N)
// 	fmt.Println("Signature valid:", valid)
// }
