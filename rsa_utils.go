package main

import "math/big"

// StringToBigInt преобразует строку в big.Int
// Использует метод SetBytes для преобразования байтового представления строки в большое целое число
func StringToBigInt(s string) *big.Int {
	return new(big.Int).SetBytes([]byte(s))
}

// BigIntToString преобразует big.Int в строку
// Использует метод Bytes для преобразования большого целого числа в байтовое представление
func BigIntToString(n *big.Int) string {
	return string(n.Bytes())
}
