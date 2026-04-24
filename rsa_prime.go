package main

import (
	"crypto/rand"
	"math/big"
)

const (
	// MillerRabinRounds — количество раундов теста Миллера-Рабина для проверки простоты
	// Чем больше раундов, тем выше достоверность результата
	MillerRabinRounds = 20
)

// isEven проверяет, является ли число чётным
// Возвращает true, если число делится на 2 без остатка
func isEven(n *big.Int) bool {
	return n.Bit(0) == 0
}

// randomNumberGen генерирует случайное нечётное число точно заданной битности
// Использует криптографически стойкий генератор псевдослучайных чисел
func randomNumberGen(bits int) (*big.Int, error) {
	// Формируем предел: 2^bits
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

// isProbablyPrime — вероятностная проверка простоты числа по алгоритму Миллера-Рабина
// Возвращает true, если число, вероятно, является простым
// Количество раундов определяет вероятность ложного срабатывания (1/2^rounds)
func isProbablyPrime(n *big.Int, rounds int) bool {
	one := big.NewInt(1)
	two := big.NewInt(2)
	three := big.NewInt(3)
	zero := big.NewInt(0)

	// 2 и 3 — простые числа
	if n.Cmp(two) == 0 || n.Cmp(three) == 0 {
		return true
	}
	// Числа меньше 2 и чётные числа — составные
	if n.Cmp(two) < 0 || isEven(n) {
		return false
	}

	// Представим n - 1 как 2^s * d, где d нечётное
	// Это необходимо для алгоритма Миллера-Рабина
	nMinusOne := new(big.Int).Sub(n, one)
	d := new(big.Int).Set(nMinusOne)
	s := 0

	for d.Bit(0) == 0 {
		d.Rsh(d, 1)
		s++
	}

	// Проводим rounds раундов теста
	for i := 0; i < rounds; i++ {
		// Выбираем случайное свидетеля a в диапазоне [2, n-2]
		max := new(big.Int).Sub(n, big.NewInt(3))
		a, err := rand.Int(rand.Reader, max)
		if err != nil {
			return false
		}
		a.Add(a, two)

		// Вычисляем a^d mod n
		x := new(big.Int).Exp(a, d, n)

		// Если a^d ≡ 1 (mod n) или a^d ≡ -1 (mod n), число, вероятно, простое
		if x.Cmp(one) == 0 || x.Cmp(nMinusOne) == 0 {
			continue
		}

		// Проводим дополнительные проверки
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

		// Если число прошло все раунды, считаем его простым
		if composite {
			return false
		}
	}

	return true
}

// generatePrime генерирует простое число заданной разрядности
// Использует перебор с проверкой по алгоритму Миллера-Рабина
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
