package main

import "math/big"

// StringToBigInt преобразует строку в big.Int
func StringToBigInt(s string) *big.Int {
	return new(big.Int).SetBytes([]byte(s))
}

// BigIntToString преобразует big.Int в строку
func BigIntToString(n *big.Int) string {
	return string(n.Bytes())
}
