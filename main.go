package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// Проверка на четность
func isEven(n *big.Int) bool {
	return n.Bit(0) == 0
}

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

// Вероятностная проверка простоты по Миллеру–Рабину
func isProbablyPrime(n *big.Int, rounds int) bool {
	one := big.NewInt(1)
	two := big.NewInt(2)
	three := big.NewInt(3)
	zero := big.NewInt(0)

	// Простые базовые случаи
	if n.Cmp(two) == 0 || n.Cmp(three) == 0 {
		return true
	}
	if n.Cmp(two) < 0 || isEven(n) {
		return false
	}

	// Представим n - 1 как 2^s * d, где d нечетное
	nMinusOne := new(big.Int).Sub(n, one)
	d := new(big.Int).Set(nMinusOne)
	s := 0

	for d.Bit(0) == 0 {
		d.Rsh(d, 1)
		s++
	}

	// rounds раундов теста
	for i := 0; i < rounds; i++ {
		// Случайное a в диапазоне [2, n-2]
		max := new(big.Int).Sub(n, big.NewInt(3))
		a, err := rand.Int(rand.Reader, max)
		if err != nil {
			return false
		}
		a.Add(a, two)

		// x = a^d mod n
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

func main() {
	n, _ := randomNumberGen(6)
	fmt.Println(n)
}
