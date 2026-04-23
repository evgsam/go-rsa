package main

import "math/big"

// Encrypt шифрует сообщение по открытому ключу: ciphertext = message^e mod n
func Encrypt(pub *PublicKey, message *big.Int) *big.Int {
	if message.Cmp(pub.N) >= 0 {
		panic("Сообщение слишком длинное!")
	}
	return new(big.Int).Exp(message, pub.E, pub.N)
}

// Decrypt расшифровывает шифротекст по закрытому ключу: message = ciphertext^d mod n
func Decrypt(priv *PrivateKey, ciphertext *big.Int) *big.Int {
	return new(big.Int).Exp(ciphertext, priv.D, priv.N)
}
