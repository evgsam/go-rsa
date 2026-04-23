package main

import (
	"bufio"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"
)

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Println("RSA Интерактивная консоль")
	fmt.Println("============================")

	// 1. Выбор размера ключа
	fmt.Print("Введите размер ключа в битах: ")
	scanner.Scan()
	bitsStr := strings.TrimSpace(scanner.Text())
	bits, _ := strconv.Atoi(bitsStr)

	// 2. Генерация ключей
	fmt.Printf("Генерирую ключи (%d бит)...\n", bits)
	pub, priv, err := GenerateKeyPair(bits)
	if err != nil {
		fmt.Printf("Ошибка: %v\n", err)
		return
	}

	fmt.Println("\nКлючи созданы успешно!")
	fmt.Printf("Открытый:  e=%s, n=%s\n", pub.E.String(), pub.N.String())
	fmt.Printf("Закрытый:  d=%s\n", priv.D.String())
	fmt.Println()

	for {
		// 3. Меню
		fmt.Println("Выберите действие:")
		fmt.Println("1. Зашифровать сообщение")
		fmt.Println("2. Расшифровать сообщение")
		fmt.Println("3. Выход")
		fmt.Print(">> ")

		scanner.Scan()
		choice := strings.TrimSpace(scanner.Text())

		switch choice {
		case "1":
			fmt.Print("Введите сообщение (короткое, max " + strconv.Itoa((pub.N.BitLen()/8)-1) + " байт): ")
			scanner.Scan()
			msg := strings.TrimSpace(scanner.Text())

			message := StringToBigInt(msg)
			if message.Cmp(pub.N) >= 0 {
				fmt.Println("Сообщение слишком длинное!")
				continue
			}

			ciphertext := Encrypt(pub, message)
			fmt.Printf("Шифротекст: %s\n", ciphertext.String())
			fmt.Printf("Оригинал:   '%s'\n", msg)

		case "2":
			fmt.Print("Введите шифротекст (число): ")
			scanner.Scan()
			ctStr := strings.TrimSpace(scanner.Text())

			ciphertext, _ := new(big.Int).SetString(ctStr, 10)
			if ciphertext == nil {
				fmt.Println("Неверный шифротекст!")
				continue
			}

			decrypted := Decrypt(priv, ciphertext)
			msg := BigIntToString(decrypted)
			fmt.Printf("Расшифровано: '%s'\n", msg)
			fmt.Printf("Число:        %s\n", decrypted.String())

		case "3":
			return

		default:
			fmt.Println("Неверный выбор")
		}
		fmt.Println()
	}
}
