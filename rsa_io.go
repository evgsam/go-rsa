package main

import (
	"fmt"
	"math/big"
	"os"
	"strings"
)

func savePublicKey(pub *PublicKey, filename string) error {
	content := fmt.Sprintf(
		"-----BEGIN RSA PUBLIC KEY-----\n"+
			"format: hex\n"+
			"e: %s\n"+
			"n: %s\n"+
			"-----END RSA PUBLIC KEY-----\n",
		pub.E.Text(16),
		pub.N.Text(16),
	)
	return os.WriteFile(filename, []byte(content), 0644)
}

func savePrivateKey(priv *PrivateKey, filename string) error {
	content := fmt.Sprintf(
		"-----BEGIN RSA PRIVATE KEY-----\n"+
			"format: hex\n"+
			"d: %s\n"+
			"n: %s\n"+
			"-----END RSA PRIVATE KEY-----\n",
		priv.D.Text(16),
		priv.N.Text(16),
	)
	return os.WriteFile(filename, []byte(content), 0600)
}

func loadPublicKey(filename string) (*PublicKey, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(data), "\n")
	var eStr, nStr string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "e: ") {
			eStr = strings.TrimPrefix(line, "e: ")
		}
		if strings.HasPrefix(line, "n: ") {
			nStr = strings.TrimPrefix(line, "n: ")
		}
	}

	if eStr == "" || nStr == "" {
		return nil, fmt.Errorf("invalid public key file format")
	}

	e, ok := new(big.Int).SetString(eStr, 16)
	if !ok {
		return nil, fmt.Errorf("invalid hex value for e")
	}

	n, ok := new(big.Int).SetString(nStr, 16)
	if !ok {
		return nil, fmt.Errorf("invalid hex value for n")
	}

	return &PublicKey{E: e, N: n}, nil
}

func loadPrivateKey(filename string) (*PrivateKey, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(data), "\n")
	var dStr, nStr string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "d: ") {
			dStr = strings.TrimPrefix(line, "d: ")
		}
		if strings.HasPrefix(line, "n: ") {
			nStr = strings.TrimPrefix(line, "n: ")
		}
	}

	if dStr == "" || nStr == "" {
		return nil, fmt.Errorf("invalid private key file format")
	}

	d, ok := new(big.Int).SetString(dStr, 16)
	if !ok {
		return nil, fmt.Errorf("invalid hex value for d")
	}

	n, ok := new(big.Int).SetString(nStr, 16)
	if !ok {
		return nil, fmt.Errorf("invalid hex value for n")
	}

	return &PrivateKey{D: d, N: n}, nil
}
