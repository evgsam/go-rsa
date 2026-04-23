package main

import "math/big"

// PublicKey представляет открытый ключ RSA
type PublicKey struct {
	N *big.Int // модуль n = p * q
	E *big.Int // открытая экспонента e (обычно 65537)
}

// PrivateKey представляет закрытый ключ RSA
type PrivateKey struct {
	N *big.Int
	D *big.Int
	P *big.Int
	Q *big.Int
	E *big.Int
}

// KeyPair представляет пару ключей RSA
type KeyPair struct {
	Public  *PublicKey  // открытый ключ
	Private *PrivateKey // закрытый ключ
}

// DefaultE — экспонента зашифрования по умолчанию
var DefaultE = big.NewInt(65537)
