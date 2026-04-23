package main

import (
	"bufio"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"
)

// savePublicKeyPEM сохраняет открытый ключ в файл
func savePublicKeyPEM(pub *PublicKey, filename string) error {
	pem := fmt.Sprintf(`-----BEGIN RSA PUBLIC KEY-----
e: %s
n: %s
-----END RSA PUBLIC KEY-----`, pub.E.String(), pub.N.String())
	return os.WriteFile(filename, []byte(pem), 0644)
}

// savePrivateKeyPEM сохраняет закрытый ключ в файл
func savePrivateKeyPEM(priv *PrivateKey, filename string) error {
	pem := fmt.Sprintf(`-----BEGIN RSA PRIVATE KEY-----
d: %s
n: %s
-----END RSA PRIVATE KEY-----`, priv.D.String(), priv.N.String())
	return os.WriteFile(filename, []byte(pem), 0600) // Только владелец!
}

// loadPublicKeyPEM загружает открытый ключ из файла
func loadPublicKeyPEM(filename string) (*PublicKey, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(data), "\n")
	eStr, nStr := "", ""
	for _, line := range lines {
		if strings.HasPrefix(line, "e: ") {
			eStr = strings.TrimPrefix(line, "e: ")
		}
		if strings.HasPrefix(line, "n: ") {
			nStr = strings.TrimPrefix(line, "n: ")
		}
	}
	e := new(big.Int)
	n := new(big.Int)
	e.SetString(eStr, 10)
	n.SetString(nStr, 10)
	return &PublicKey{E: e, N: n}, nil
}

// loadPrivateKeyPEM загружает закрытый ключ из файла
func loadPrivateKeyPEM(filename string) (*PrivateKey, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(string(data), "\n")
	dStr, nStr := "", ""
	for _, line := range lines {
		if strings.HasPrefix(line, "d: ") {
			dStr = strings.TrimPrefix(line, "d: ")
		}
		if strings.HasPrefix(line, "n: ") {
			nStr = strings.TrimPrefix(line, "n: ")
		}
	}
	d := new(big.Int)
	n := new(big.Int)
	d.SetString(dStr, 10)
	n.SetString(nStr, 10)
	return &PrivateKey{D: d, N: n}, nil
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)

	for {
		fmt.Println("\n RSA CLI")
		fmt.Println("1. Сгенерировать ключевую пару")
		fmt.Println("2. Зашифровать сообщение")
		fmt.Println("3. Расшифровать сообщение")
		fmt.Println("4. Выход")
		fmt.Print(">> ")

		if !scanner.Scan() {
			return
		}
		choice := strings.TrimSpace(scanner.Text())

		switch choice {
		case "1":
			fmt.Print("Введите длину ключа в битах (например, 128, 256, 512): ")
			if !scanner.Scan() {
				return
			}
			bitsStr := strings.TrimSpace(scanner.Text())
			bits, err := strconv.Atoi(bitsStr)
			if err != nil || bits < 32 {
				fmt.Println("Некорректная длина ключа")
				continue
			}

			fmt.Println("Генерация ключей...")
			pub, priv, err := GenerateKeyPair(bits)
			if err != nil {
				fmt.Printf("Ошибка генерации: %v\n", err)
				continue
			}

			pubPath := fmt.Sprintf("rsa-%d.pub", bits)
			privPath := fmt.Sprintf("rsa-%d.pem", bits)

			if err := savePublicKeyPEM(pub, pubPath); err != nil {
				fmt.Printf("Ошибка сохранения открытого ключа: %v\n", err)
				continue
			}
			if err := savePrivateKeyPEM(priv, privPath); err != nil {
				fmt.Printf("Ошибка сохранения закрытого ключа: %v\n", err)
				continue
			}

			fmt.Println("Ключевая пара создана")
			fmt.Printf("Открытый ключ: %s\n", pubPath)
			fmt.Printf("Закрытый ключ: %s\n", privPath)

		case "2":
			fmt.Print("Введите путь к открытому ключу: ")
			if !scanner.Scan() {
				return
			}
			pubPath := strings.TrimSpace(scanner.Text())

			pub, err := loadPublicKeyPEM(pubPath)
			if err != nil {
				fmt.Printf("Ошибка загрузки открытого ключа: %v\n", err)
				continue
			}

			maxBytes := (pub.N.BitLen() / 8) - 1
			if maxBytes <= 0 {
				fmt.Println("Некорректный ключ")
				continue
			}

			fmt.Printf("Введите короткое сообщение (до %d байт): ", maxBytes)
			if !scanner.Scan() {
				return
			}
			msg := scanner.Text()

			m := StringToBigInt(msg)
			if m.Cmp(pub.N) >= 0 {
				fmt.Println("Сообщение слишком длинное для этого ключа")
				continue
			}

			c := Encrypt(pub, m)
			fmt.Println("Шифрование выполнено")
			fmt.Printf("Шифротекст: %s\n", c.String())

		case "3":
			fmt.Print("Введите путь к закрытому ключу: ")
			if !scanner.Scan() {
				return
			}
			privPath := strings.TrimSpace(scanner.Text())

			priv, err := loadPrivateKeyPEM(privPath)
			if err != nil {
				fmt.Printf("Ошибка загрузки закрытого ключа: %v\n", err)
				continue
			}

			fmt.Print("Введите шифротекст: ")
			if !scanner.Scan() {
				return
			}
			cipherStr := strings.TrimSpace(scanner.Text())

			c, ok := new(big.Int).SetString(cipherStr, 10)
			if !ok {
				fmt.Println("Шифротекст должен быть целым числом")
				continue
			}

			m := Decrypt(priv, c)
			fmt.Println("Расшифрование выполнено")
			fmt.Printf("Открытый текст: %s\n", BigIntToString(m))

		case "4":
			fmt.Println("Выход.")
			return

		default:
			fmt.Println("Неверный пункт меню")
		}
	}
}
