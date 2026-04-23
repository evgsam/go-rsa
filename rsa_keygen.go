package main

import (
	"math/big"
)

// extendedEvklid — расширенный алгоритм Евклида для вычисления обратного элемента
func extendedEvklid(e, phi *big.Int) (x *big.Int) {
	x0, y0, x1, y1 := new(big.Int), new(big.Int), new(big.Int), new(big.Int)
	x0.SetInt64(1)
	x1.SetInt64(0)
	y0.SetInt64(0)
	y1.SetInt64(1)
	a := new(big.Int).Set(e)
	b := new(big.Int).Set(phi)

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
func GenerateKeyPair(bits int) (*PublicKey, *PrivateKey, error) {
	p, err := generatePrime(bits/2, MillerRabinRounds)
	if err != nil {
		return nil, nil, err
	}

	q, err := generatePrime(bits/2, MillerRabinRounds)
	if err != nil {
		return nil, nil, err
	}

	// Гарантируем, что p ≠ q
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

	n := new(big.Int).Mul(p, q)
	phi := new(big.Int).Mul(
		new(big.Int).Sub(p, big.NewInt(1)),
		new(big.Int).Sub(q, big.NewInt(1)),
	)

	// Проверяем взаимную простоту e и φ(n)
	if new(big.Int).GCD(nil, nil, DefaultE, phi).Cmp(big.NewInt(1)) != 0 {
		return GenerateKeyPair(bits)
	}

	d := new(big.Int).Mod(extendedEvklid(DefaultE, phi), phi)
	return &PublicKey{E: DefaultE, N: n}, &PrivateKey{D: d, N: n}, nil
}
