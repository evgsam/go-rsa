package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"strings"
)

// savePublicKey сохраняет открытый ключ в файл в формате PEM (PKCS#1)
// Формирует стандартный PEM-блок и записывает его на диск с правами 0644
func savePublicKey(pub *PublicKey, filename string) error {
	// Преобразуем наш ключ в стандартный тип rsa.PublicKey
	rsaPub := &rsa.PublicKey{
		N: pub.N,
		E: int(pub.E.Int64()),
	}

	// Формируем PEM-блок с типом "RSA PUBLIC KEY"
	block := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(rsaPub),
	}

	// Записываем файл с правами 0644 (чтение и запись для владельца, чтение для остальных)
	return os.WriteFile(filename, pem.EncodeToMemory(block), 0644)
}

// savePrivateKey сохраняет закрытый ключ в файл в формате PEM (PKCS#1)
// Валидирует ключ перед сохранением и записывает с правами 0600
func savePrivateKey(priv *PrivateKey, filename string) error {
	// Преобразуем наш ключ в стандартный тип rsa.PrivateKey
	rsaPriv := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: priv.N,
			E: int(priv.E.Int64()),
		},
		D:      priv.D,
		Primes: []*big.Int{priv.P, priv.Q},
	}

	// Валидируем ключ (проверяем корректность всех параметров)
	if err := rsaPriv.Validate(); err != nil {
		return err
	}

	// Формируем PEM-блок с типом "RSA PRIVATE KEY"
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(rsaPriv),
	}
	// Записываем файл с правами 0600 (только чтение и запись для владельца)
	return os.WriteFile(filename, pem.EncodeToMemory(block), 0600)
}

// loadPublicKey загружает открытый ключ из файла в формате PEM
// Возвращает разобранный ключ или ошибку при некорректном формате
func loadPublicKey(filename string) (*PublicKey, error) {
	// Читаем содержимое файла
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	// Декодируем PEM-блок
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "RSA PUBLIC KEY" {
		return nil, fmt.Errorf("invalid PEM public key")
	}

	// Парсим ключ в формате PKCS#1
	rsaPub, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	// Формируем наш тип PublicKey
	return &PublicKey{
		N: rsaPub.N,
		E: big.NewInt(int64(rsaPub.E)),
	}, nil
}

// loadPrivateKey загружает закрытый ключ из файла в формате PEM
// Возвращает разобранный ключ или ошибку при некорректном формате
func loadPrivateKey(filename string) (*PrivateKey, error) {
	// Читаем содержимое файла
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	// Декодируем PEM-блок
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("invalid PEM private key")
	}

	// Парсим ключ в формате PKCS#1
	rsaPriv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	// Формируем наш тип PrivateKey
	return &PrivateKey{
		N: rsaPriv.N,
		D: rsaPriv.D,
		P: rsaPriv.Primes[0],
		Q: rsaPriv.Primes[1],
		E: big.NewInt(int64(rsaPriv.E)),
	}, nil
}

// readTextFile читает текстовый файл и возвращает его содержимое как строку
func readTextFile(filename string) (string, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// writeTextFile записывает строку в текстовый файл
func writeTextFile(filename, text string) error {
	return os.WriteFile(filename, []byte(text), 0644)
}

// writeCiphertextFile записывает шифротекст в файл в шестнадцатеричном формате
func writeCiphertextFile(filename string, c *big.Int) error {
	hexText := c.Text(16)
	return os.WriteFile(filename, []byte(hexText), 0644)
}

// readCiphertextFile читает шифротекст из файла (ожидается hex-формат)
// Возвращает big.Int значение шифротекста или ошибку
func readCiphertextFile(filename string) (*big.Int, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	s := strings.TrimSpace(string(data))
	if s == "" {
		return nil, fmt.Errorf("empty ciphertext file")
	}

	// Парсим шестнадцатеричную строку в big.Int
	c := new(big.Int)
	_, ok := c.SetString(s, 16)
	if !ok {
		return nil, fmt.Errorf("invalid hex ciphertext")
	}

	return c, nil
}
