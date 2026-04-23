package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

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
				fmt.Println("❌ Некорректная длина ключа")
				continue
			}

			fmt.Println("Генерация ключей...")
			pub, priv, err := GenerateKeyPair(bits)
			if err != nil {
				fmt.Printf("❌ Ошибка генерации: %v\n", err)
				continue
			}

			pubPath := fmt.Sprintf("rsa-%d-pub.hex", bits)
			privPath := fmt.Sprintf("rsa-%d-priv.hex", bits)

			if err := savePublicKeyHEX(pub, pubPath); err != nil {
				fmt.Printf("❌ Ошибка сохранения открытого ключа: %v\n", err)
				continue
			}
			if err := savePrivateKeyHEX(priv, privPath); err != nil {
				fmt.Printf("❌ Ошибка сохранения закрытого ключа: %v\n", err)
				continue
			}

			fmt.Println("✅ Ключевая пара создана")
			fmt.Printf("Открытый ключ: %s\n", pubPath)
			fmt.Printf("Закрытый ключ: %s\n", privPath)

		case "2":
			fmt.Print("Введите путь к открытому ключу: ")
			if !scanner.Scan() {
				return
			}
			pubPath := strings.TrimSpace(scanner.Text())

			pub, err := loadPublicKeyHEX(pubPath)
			if err != nil {
				fmt.Printf("❌ Ошибка загрузки открытого ключа: %v\n", err)
				continue
			}

			maxBytes := (pub.N.BitLen() / 8) - 1
			if maxBytes <= 0 {
				fmt.Println("❌ Некорректный ключ")
				continue
			}

			fmt.Printf("Введите короткое сообщение (до %d байт): ", maxBytes)
			if !scanner.Scan() {
				return
			}
			msg := scanner.Text()

			m := StringToBigInt(msg)
			if m.Cmp(pub.N) >= 0 {
				fmt.Println("❌ Сообщение слишком длинное для этого ключа")
				continue
			}

			c := Encrypt(pub, m)
			fmt.Println("✅ Шифрование выполнено")
			fmt.Printf("Шифротекст (hex): %s\n", c.Text(16))

			ctPath := fmt.Sprintf("ciphertext-%d.hex", pub.N.BitLen())
			if err := saveCiphertextHEX(c, ctPath); err != nil {
				fmt.Printf("❌ Ошибка сохранения шифротекста: %v\n", err)
				continue
			}
			fmt.Printf("Шифротекст сохранён: %s\n", ctPath)

		case "3":
			fmt.Print("Введите путь к закрытому ключу: ")
			if !scanner.Scan() {
				return
			}
			privPath := strings.TrimSpace(scanner.Text())

			priv, err := loadPrivateKeyHEX(privPath)
			if err != nil {
				fmt.Printf("❌ Ошибка загрузки закрытого ключа: %v\n", err)
				continue
			}

			fmt.Print("Введите путь к шифротексту (hex): ")
			if !scanner.Scan() {
				return
			}
			ctPath := strings.TrimSpace(scanner.Text())

			c, err := loadCiphertextHEX(ctPath)
			if err != nil {
				fmt.Printf("❌ Ошибка загрузки шифротекста: %v\n", err)
				continue
			}

			m := Decrypt(priv, c)
			fmt.Println("✅ Расшифрование выполнено")
			fmt.Printf("Открытый текст: %s\n", BigIntToString(m))

		case "4":
			fmt.Println("Выход.")
			return

		default:
			fmt.Println("❌ Неверный пункт меню")
		}
	}
}
