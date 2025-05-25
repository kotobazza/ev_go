package zkp

import (
	"ev/internal/crypto/bigint"
	"fmt"
)

// CorrectMessageProof реализует доказательство допустимости зашифрованного сообщения
type CorrectMessageProof struct {
	EVals         []*bigint.BigInt
	ZVals         []*bigint.BigInt
	AVals         []*bigint.BigInt
	B             uint
	ciphertext    *bigint.BigInt
	validMessages []*bigint.BigInt
	n             *bigint.BigInt
	nn            *bigint.BigInt
}

// NewCorrectMessageProof создаёт ZKP-доказательство из готовых векторов
func NewCorrectMessageProof(eVec, zVec, aVec []*bigint.BigInt, cipher *bigint.BigInt, validMsgs []*bigint.BigInt, n *bigint.BigInt, b uint) *CorrectMessageProof {
	return &CorrectMessageProof{
		EVals:         eVec,
		ZVals:         zVec,
		AVals:         aVec,
		ciphertext:    cipher,
		validMessages: validMsgs,
		n:             n,
		nn:            n.Mul(n),
		B:             b,
	}
}

// Prove создает новое доказательство для заданного сообщения
func Prove(n *bigint.BigInt, validMessages []*bigint.BigInt, messageToEncrypt *bigint.BigInt) *CorrectMessageProof {
	nn := n.Mul(n)
	numOfMessages := len(validMessages)

	// Генерация случайного r и шифрование сообщения
	var r *bigint.BigInt
	two := bigint.NewBigIntFromInt(2)
	for {
		r = randomInRange(two, n)
		if bigint.GCD(r, n).Eq(bigint.NewBigIntFromInt(1)) {
			break
		}
	}

	// Шифрование сообщения
	g := n.Add(bigint.NewBigIntFromInt(1)) // Стандартное значение g для Paillier
	ciphertext := g.ModExp(messageToEncrypt, nn).Mul(r.ModExp(n, nn)).Mod(nn)

	// Вычисление u_i для каждого допустимого сообщения
	uiVec := make([]*bigint.BigInt, numOfMessages)
	for i, m := range validMessages {
		gm := g.ModExp(m, nn)
		gmInv, _ := gm.ModInverse(nn)
		ui := ciphertext.Mul(gmInv).Mod(nn)
		uiVec[i] = ui
	}

	// Генерация случайных e_j и z_j для всех сообщений, кроме истинного
	B := uint(256) // Параметр безопасности
	twoToB := two.Lsh(B)

	eiVec := make([]*bigint.BigInt, numOfMessages-1)
	ziVec := make([]*bigint.BigInt, numOfMessages-1)
	for i := 0; i < numOfMessages-1; i++ {
		eiVec[i] = randomInRange(bigint.NewBigIntFromInt(0), twoToB)
		ziVec[i] = randomInRange(two, n)
	}

	// Генерация случайного w
	w := randomInRange(two, n)

	// Находим индекс истинного сообщения
	trueIndex := -1
	for i, m := range validMessages {
		if m.Eq(messageToEncrypt) {
			trueIndex = i
			break
		}
	}
	if trueIndex == -1 {
		panic("message not found in valid messages")
	}

	// Вычисляем a_i для каждого сообщения
	aiVec := make([]*bigint.BigInt, numOfMessages)
	j := 0
	for i := 0; i < numOfMessages; i++ {
		if i == trueIndex {
			aiVec[i] = w.ModExp(n, nn)
		} else {
			ziN := ziVec[j].ModExp(n, nn)
			uiEi := uiVec[i].ModExp(eiVec[j], nn)
			uiEiInv, _ := uiEi.ModInverse(nn)
			aiVec[i] = ziN.Mul(uiEiInv).Mod(nn)
			j++
		}
	}

	// Вычисляем challenge (chal)
	chal := computeDigest(aiVec).Mod(twoToB)
	fmt.Println("Go chal:", chal.ToString())

	// Вычисляем e_i для истинного сообщения
	eiSum := bigint.NewBigIntFromInt(0)
	for _, ei := range eiVec {
		eiSum = eiSum.Add(ei).Mod(twoToB)
	}
	fmt.Println("Go eiSum:", eiSum.ToString())

	// Вычисляем ei для истинного сообщения: (chal - eiSum + twoToB) % twoToB
	ei := chal.Sub(eiSum).Add(twoToB).Mod(twoToB)
	fmt.Println("Go ei for true message:", ei.ToString())

	// Вычисляем z_i для истинного сообщения
	riEi := r.ModExp(ei, n)
	zi := w.Mul(riEi).Mod(n)

	// Собираем полные векторы e_vec и z_vec
	eVec := make([]*bigint.BigInt, numOfMessages)
	zVec := make([]*bigint.BigInt, numOfMessages)
	j = 0
	for i := 0; i < numOfMessages; i++ {
		if i == trueIndex {
			eVec[i] = ei
			zVec[i] = zi
		} else {
			eVec[i] = eiVec[j]
			zVec[i] = ziVec[j]
			j++
		}
	}

	return NewCorrectMessageProof(eVec, zVec, aiVec, ciphertext, validMessages, n, B)
}

// Verify проверяет доказательство допустимости
func (proof *CorrectMessageProof) Verify() bool {
	twoToB := bigint.NewBigIntFromInt(1).Lsh(proof.B)
	fmt.Println("Go twoToB:", twoToB.ToString())

	// Проверка суммы e_i
	chal := computeDigest(proof.AVals).Mod(twoToB)
	fmt.Println("Go verification chal:", chal.ToString())

	eiSum := bigint.NewBigIntFromInt(0)
	for _, e := range proof.EVals {
		fmt.Println("Go e:", e.ToString())
		eiSum = eiSum.Add(e).Mod(twoToB)
	}
	fmt.Println("Go verification eiSum:", eiSum.ToString())

	if !chal.Eq(eiSum) {
		fmt.Println("Go: Challenge check failed")
		return false
	}

	fmt.Println("Go: Challenge check passed")

	// Вычисление u_i для каждого допустимого сообщения
	g := proof.n.Add(bigint.NewBigIntFromInt(1))
	uiVec := make([]*bigint.BigInt, len(proof.validMessages))
	for i, m := range proof.validMessages {
		gm := g.ModExp(m, proof.nn)
		gmInv, _ := gm.ModInverse(proof.nn)
		ui := proof.ciphertext.Mul(gmInv).Mod(proof.nn)
		uiVec[i] = ui
	}

	// Проверка каждого уравнения z_i^n ≡ a_i * u_i^e_i mod n²
	for i := 0; i < len(proof.validMessages); i++ {
		ziN := proof.ZVals[i].ModExp(proof.n, proof.nn)
		uiEi := uiVec[i].ModExp(proof.EVals[i], proof.nn)
		rightSide := proof.AVals[i].Mul(uiEi).Mod(proof.nn)

		fmt.Printf("Go equation %d:\n", i)
		fmt.Println("  ziN:", ziN.ToString())
		fmt.Println("  rightSide:", rightSide.ToString())

		if !ziN.Eq(rightSide) {
			fmt.Printf("Go: Equation %d check failed\n", i)
			return false
		}
	}

	return true
}
