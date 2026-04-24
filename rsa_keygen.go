package main

import (
	"math/big"
)

// extendedEvklid — расширенный алгоритм Евклида для вычисления обратного элемента
// Вычисляет d = e^(-1) mod phi(n), то есть число d, такое что e*d ≡ 1 (mod phi(n))
// Результат — мультипликативная обратная величина e по модулю phi
func extendedEvklid(e, phi *big.Int) (x *big.Int) {
	// Инициализация переменных для расширенного алгоритма Евклида
	x0, y0, x1, y1 := new(big.Int), new(big.Int), new(big.Int), new(big.Int)
	x0.SetInt64(1)
	x1.SetInt64(0)
	y0.SetInt64(0)
	y1.SetInt64(1)
	a := new(big.Int).Set(e)
	b := new(big.Int).Set(phi)

	// Выполняем алгоритм Евклида
	for b.Cmp(big.NewInt(0)) != 0 {
		q := new(big.Int).Div(a, b)
		r := new(big.Int).Mod(a, b)
		x2 := new(big.Int).Sub(x0, new(big.Int).Mul(q, x1))
		y2 := new(big.Int).Sub(y0, new(big.Int).Mul(q, y1))
		a = b
		b = r
		x0, x1 = x1, x2
		y0, y1 = y1, y2
	}
	return new(big.Int).Set(x0)
}

// GenerateKeyPair генерирует пару RSA-ключей заданной разрядности
// Возвращает открытый ключ, закрытый ключ и возможную ошибку
// Алгоритм:
// 1. Генерируем два простых числа p и q заданной длины
// 2. Вычисляем модуль n = p * q
// 3. Вычисляем функцию Эйлера phi(n) = (p-1) * (q-1)
// 4. Выбираем экспоненту e, взаимно простую с phi(n)
// 5. Вычисляем закрытую экспоненту d = e^(-1) mod phi(n)
func GenerateKeyPair(bits int) (*PublicKey, *PrivateKey, error) {
	// Генерируем первое простое число p
	p, err := generatePrime(bits/2, MillerRabinRounds)
	if err != nil {
		return nil, nil, err
	}

	// Генерируем второе простое число q
	q, err := generatePrime(bits/2, MillerRabinRounds)
	if err != nil {
		return nil, nil, err
	}

	// Гарантируем, что p ≠ q (два простых числа должны отличаться)
	for {
		if q.Cmp(p) == 0 {
			q, err = generatePrime(bits/2, MillerRabinRounds)
			if err != nil {
				return nil, nil, err
			}
		} else {
			break
		}
	}

	// Вычисляем модуль n = p * q
	n := new(big.Int).Mul(p, q)
	// Вычисляем phi(n) = (p-1) * (q-1)
	phi := new(big.Int).Mul(
		new(big.Int).Sub(p, big.NewInt(1)),
		new(big.Int).Sub(q, big.NewInt(1)),
	)

	// Проверяем взаимную простоту e и phi(n): gcd(e, phi) == 1
	// Если не взаимно просты — рекурсивно вызываем генерацию заново
	if new(big.Int).GCD(nil, nil, DefaultE, phi).Cmp(big.NewInt(1)) != 0 {
		return GenerateKeyPair(bits)
	}

	// Вычисляем закрытую экспоненту d = e^(-1) mod phi(n)
	d := new(big.Int).Mod(extendedEvklid(DefaultE, phi), phi)

	// Формируем открытый ключ
	pub := &PublicKey{
		E: new(big.Int).Set(DefaultE),
		N: new(big.Int).Set(n),
	}

	// Формируем закрытый ключ
	priv := &PrivateKey{
		N: new(big.Int).Set(n),
		D: new(big.Int).Set(d),
		P: new(big.Int).Set(p),
		Q: new(big.Int).Set(q),
		E: new(big.Int).Set(DefaultE),
	}

	return pub, priv, nil
}
