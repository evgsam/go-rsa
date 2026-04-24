package main

import "math/big"

// Encrypt шифрует сообщение по открытому ключу: ciphertext = message^e mod n
// Использует формулу RSA: C = M^e mod n
// Возвращает шифротекст в виде big.Int
// Если сообщение слишком длинное (message >= n), происходит паника
func Encrypt(pub *PublicKey, message *big.Int) *big.Int {
	if message.Cmp(pub.N) >= 0 {
		panic("Сообщение слишком длинное!")
	}
	// Возведение в степень по модулю: message^e mod n
	return new(big.Int).Exp(message, pub.E, pub.N)
}

// Decrypt расшифровывает шифротекст по закрытому ключу: message = ciphertext^d mod n
// Использует формулу RSA: M = C^d mod n
// Возвращает открытый текст в виде big.Int
func Decrypt(priv *PrivateKey, ciphertext *big.Int) *big.Int {
	// Возведение в степень по модулю: ciphertext^d mod n
	return new(big.Int).Exp(ciphertext, priv.D, priv.N)
}
