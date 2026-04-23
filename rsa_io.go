package main

import (
	"fmt"
	"math/big"
	"os"
	"strings"
)

// savePublicKeyHEX сохраняет открытый ключ в hex-формате
func savePublicKeyHEX(pub *PublicKey, filename string) error {
	content := fmt.Sprintf("e: %s\nn: %s\n", pub.E.Text(16), pub.N.Text(16))
	return os.WriteFile(filename, []byte(content), 0644)
}

// savePrivateKeyHEX сохраняет закрытый ключ в hex-формате
func savePrivateKeyHEX(priv *PrivateKey, filename string) error {
	content := fmt.Sprintf("d: %s\nn: %s\n", priv.D.Text(16), priv.N.Text(16))
	return os.WriteFile(filename, []byte(content), 0600)
}

// loadPublicKeyHEX загружает открытый ключ из hex-формата
func loadPublicKeyHEX(filename string) (*PublicKey, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(data), "\n")
	eStr, nStr := "", ""
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "e: ") {
			eStr = strings.TrimPrefix(line, "e: ")
		}
		if strings.HasPrefix(line, "n: ") {
			nStr = strings.TrimPrefix(line, "n: ")
		}
	}
	e := new(big.Int)
	n := new(big.Int)
	e.SetString(eStr, 16)
	n.SetString(nStr, 16)
	return &PublicKey{E: e, N: n}, nil
}

// loadPrivateKeyHEX загружает закрытый ключ из hex-формата
func loadPrivateKeyHEX(filename string) (*PrivateKey, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(data), "\n")
	dStr, nStr := "", ""
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "d: ") {
			dStr = strings.TrimPrefix(line, "d: ")
		}
		if strings.HasPrefix(line, "n: ") {
			nStr = strings.TrimPrefix(line, "n: ")
		}
	}
	d := new(big.Int)
	n := new(big.Int)
	d.SetString(dStr, 16)
	n.SetString(nStr, 16)
	return &PrivateKey{D: d, N: n}, nil
}

// saveCiphertextHEX сохраняет шифротекст в hex-формате
func saveCiphertextHEX(ciphertext *big.Int, filename string) error {
	content := fmt.Sprintf("ciphertext: %s\n", ciphertext.Text(16))
	return os.WriteFile(filename, []byte(content), 0644)
}

// loadCiphertextHEX загружает шифротекст из hex-формата
func loadCiphertextHEX(filename string) (*big.Int, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(data), "\n")
	cStr := ""
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ciphertext: ") {
			cStr = strings.TrimPrefix(line, "ciphertext: ")
		}
	}
	c := new(big.Int)
	c.SetString(cStr, 16)
	return c, nil
}
