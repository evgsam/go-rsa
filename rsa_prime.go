package main

import (
	"crypto/rand"
	"math/big"
)

const (
	MillerRabinRounds = 20
	DefaultKeyBits    = 2048
)

// isEven проверяет, является ли число чётным
func isEven(n *big.Int) bool {
	return n.Bit(0) == 0
}

// randomNumberGen генерирует случайное нечётное число точно заданной битности
func randomNumberGen(bits int) (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), uint(bits))
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, err
	}
	// Установить старший бит, чтобы число точно было нужной битности
	n.SetBit(n, bits-1, 1)
	// Установить младший бит, чтобы число было нечётным
	n.SetBit(n, 0, 1)
	return n, nil
}

// isProbablyPrime — вероятностная проверка простоты по Миллеру-Рабину
func isProbablyPrime(n *big.Int, rounds int) bool {
	one := big.NewInt(1)
	two := big.NewInt(2)
	three := big.NewInt(3)
	zero := big.NewInt(0)

	if n.Cmp(two) == 0 || n.Cmp(three) == 0 {
		return true
	}
	if n.Cmp(two) < 0 || isEven(n) {
		return false
	}

	// Представим n - 1 как 2^s * d, где d нечётное
	nMinusOne := new(big.Int).Sub(n, one)
	d := new(big.Int).Set(nMinusOne)
	s := 0

	for d.Bit(0) == 0 {
		d.Rsh(d, 1)
		s++
	}

	for i := 0; i < rounds; i++ {
		max := new(big.Int).Sub(n, big.NewInt(3))
		a, err := rand.Int(rand.Reader, max)
		if err != nil {
			return false
		}
		a.Add(a, two)

		x := new(big.Int).Exp(a, d, n)

		if x.Cmp(one) == 0 || x.Cmp(nMinusOne) == 0 {
			continue
		}

		composite := true
		for r := 1; r < s; r++ {
			x.Exp(x, two, n)
			if x.Cmp(nMinusOne) == 0 {
				composite = false
				break
			}
			if x.Cmp(zero) == 0 {
				return false
			}
		}

		if composite {
			return false
		}
	}

	return true
}

// generatePrime генерирует простое число заданной разрядности
func generatePrime(bits int, rounds int) (*big.Int, error) {
	for {
		candidate, err := randomNumberGen(bits)
		if err != nil {
			return nil, err
		}
		if isProbablyPrime(candidate, rounds) {
			return candidate, nil
		}
	}
}
