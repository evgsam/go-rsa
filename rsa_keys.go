package main

import "math/big"

// PublicKey представляет открытый ключ RSA
type PublicKey struct {
	N *big.Int // модуль n = p * q
	E *big.Int // открытая экспонента e (обычно 65537)
}

// PrivateKey представляет закрытый ключ RSA
type PrivateKey struct {
	N *big.Int // тот же модуль n
	D *big.Int // закрытая экспонента d = e^(-1) mod φ(n)
}

// KeyPair представляет пару ключей RSA
type KeyPair struct {
	Public  *PublicKey  // открытый ключ
	Private *PrivateKey // закрытый ключ
}

// DefaultE — экспонента зашифрования по умолчанию
var DefaultE = big.NewInt(65537)
