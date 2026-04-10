package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// --------------------------
// генерирайция случайного нечетного числа точно заданной битности для использования в качестве кандидата на простое число в RSA.
// --------------------------
func randomNumberGen(bits int) (*big.Int, error) {
	//верхняя граница случайного числа
	limit := new(big.Int).Lsh(big.NewInt(1), uint(bits))
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, err
	}
	// Установить старший бит, чтобы число точно было нужной битности
	// на случай что сгенерировалось меньше
	n.SetBit(n, bits-1, 1)

	// Установить младший бит, чтобы число было нечетным
	n.SetBit(n, 0, 1)
	return n, nil
}

func main() {
	n, _ := randomNumberGen(6)
	fmt.Println(n)
}
