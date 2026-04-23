package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
)

func savePublicKey(pub *PublicKey, filename string) error {
	rsaPub := &rsa.PublicKey{
		N: pub.N,
		E: int(pub.E.Int64()),
	}

	block := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(rsaPub),
	}

	return os.WriteFile(filename, pem.EncodeToMemory(block), 0644)
}

func savePrivateKey(priv *PrivateKey, filename string) error {
	rsaPriv := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: priv.N,
			E: int(priv.E.Int64()),
		},
		D:      priv.D,
		Primes: []*big.Int{priv.P, priv.Q},
	}

	if err := rsaPriv.Validate(); err != nil {
		return err
	}

	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(rsaPriv),
	}
	return os.WriteFile(filename, pem.EncodeToMemory(block), 0600)
}

func loadPublicKey(filename string) (*PublicKey, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil || block.Type != "RSA PUBLIC KEY" {
		return nil, fmt.Errorf("invalid PEM public key")
	}

	rsaPub, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return &PublicKey{
		N: rsaPub.N,
		E: big.NewInt(int64(rsaPub.E)),
	}, nil
}

func loadPrivateKey(filename string) (*PrivateKey, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("invalid PEM private key")
	}

	rsaPriv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return &PrivateKey{
		N: rsaPriv.N,
		D: rsaPriv.D,
		P: rsaPriv.Primes[0],
		Q: rsaPriv.Primes[1],
		E: big.NewInt(int64(rsaPriv.E)),
	}, nil
}
