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
	// Инициализируем сканер для чтения ввода пользователя
	scanner := bufio.NewScanner(os.Stdin)

	// Основной цикл программы — отображение меню до выбора выхода
	for {
		fmt.Println("1. Сгенерировать ключевую пару")
		fmt.Println("2. Зашифровать сообщение из командной строки")
		fmt.Println("3. Расшифровать сообщение из командной строки")
		fmt.Println("4. Зашифровать файл")
		fmt.Println("5. Расшифровать файл")
		fmt.Println("6. Выход")
		fmt.Print(">> ")

		if !scanner.Scan() {
			return
		}
		choice := strings.TrimSpace(scanner.Text())

		switch choice {
		// Генерация ключевой пары RSA
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

			// Формируем имена файлов ключей с указанием разрядности
			pubPath := fmt.Sprintf("rsa-%d.pub", bits)
			privPath := fmt.Sprintf("rsa-%d.pem", bits)

			// Сохраняем открытый ключ в файл
			if err := savePublicKey(pub, pubPath); err != nil {
				fmt.Printf("Ошибка сохранения открытого ключа: %v\n", err)
				continue
			}
			// Сохраняем закрытый ключ в файл
			if err := savePrivateKey(priv, privPath); err != nil {
				fmt.Printf("Ошибка сохранения закрытого ключа: %v\n", err)
				continue
			}

			fmt.Println("Ключевая пара создана")
			fmt.Printf("Открытый ключ: %s\n", pubPath)
			fmt.Printf("Закрытый ключ: %s\n", privPath)

		// Шифрование короткого сообщения из командной строки
		case "2":
			fmt.Print("Введите путь к открытому ключу: ")
			if !scanner.Scan() {
				return
			}
			pubPath := strings.TrimSpace(scanner.Text())

			// Загружаем открытый ключ
			pub, err := loadPublicKey(pubPath)
			if err != nil {
				fmt.Printf("Ошибка загрузки открытого ключа: %v\n", err)
				continue
			}

			// Вычисляем максимальную длину сообщения для данного ключа
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

			// Преобразуем строку сообщения в big.Int
			m := StringToBigInt(msg)
			// Проверяем, что сообщение не превышает размер модуля ключа
			if m.Cmp(pub.N) >= 0 {
				fmt.Println("Сообщение слишком длинное для этого ключа")
				continue
			}

			// Шифруем сообщение
			c := Encrypt(pub, m)
			fmt.Println("Шифрование выполнено")
			fmt.Printf("Шифротекст (hex): %s\n", c.Text(16))

		// Расшифрование короткого сообщения из командной строки
		case "3":
			fmt.Print("Введите путь к закрытому ключу: ")
			if !scanner.Scan() {
				return
			}
			privPath := strings.TrimSpace(scanner.Text())

			// Загружаем закрытый ключ
			priv, err := loadPrivateKey(privPath)
			if err != nil {
				fmt.Printf("Ошибка загрузки закрытого ключа: %v\n", err)
				continue
			}

			fmt.Print("Введите шифротекст (hex): ")
			if !scanner.Scan() {
				return
			}
			ctHex := strings.TrimSpace(scanner.Text())

			// Преобразуем hex-строку шифротекста в big.Int
			c := new(big.Int)
			c.SetString(ctHex, 16)
			if c == nil {
				fmt.Println("Шифротекст должен быть числом в hex-формате")
				continue
			}

			// Расшифровываем шифротекст
			m := Decrypt(priv, c)
			fmt.Println("Расшифрование выполнено")
			fmt.Printf("Открытый текст: %s\n", BigIntToString(m))

		// Шифрование файла
		case "4":
			fmt.Print("Введите путь к открытому ключу: ")
			if !scanner.Scan() {
				return
			}
			pubPath := strings.TrimSpace(scanner.Text())

			// Загружаем открытый ключ
			pub, err := loadPublicKey(pubPath)
			if err != nil {
				fmt.Printf("Ошибка загрузки открытого ключа: %v\n", err)
				continue
			}

			fmt.Print("Введите путь к файлу с открытым текстом: ")
			if !scanner.Scan() {
				return
			}
			inputPath := strings.TrimSpace(scanner.Text())

			// Читаем содержимое файла
			text, err := readTextFile(inputPath)
			if err != nil {
				fmt.Printf("Ошибка чтения файла: %v\n", err)
				continue
			}

			// Преобразуем содержимое в big.Int и проверяем длину
			m := StringToBigInt(text)
			if m.Cmp(pub.N) >= 0 {
				fmt.Println("Содержимое файла слишком длинное для этого ключа")
				continue
			}

			// Шифруем содержимое
			c := Encrypt(pub, m)

			fmt.Print("Введите путь для сохранения шифртекста: ")
			if !scanner.Scan() {
				return
			}
			outputPath := strings.TrimSpace(scanner.Text())

			// Сохраняем шифротекст в файл (в hex-формате)
			if err := writeCiphertextFile(outputPath, c); err != nil {
				fmt.Printf("Ошибка записи шифртекста: %v\n", err)
				continue
			}

			fmt.Println("Шифрование файла выполнено")

		// Расшифрование файла
		case "5":
			fmt.Print("Введите путь к закрытому ключу: ")
			if !scanner.Scan() {
				return
			}
			privPath := strings.TrimSpace(scanner.Text())

			// Загружаем закрытый ключ
			priv, err := loadPrivateKey(privPath)
			if err != nil {
				fmt.Printf("Ошибка загрузки закрытого ключа: %v\n", err)
				continue
			}

			fmt.Print("Введите путь к файлу с шифртекстом: ")
			if !scanner.Scan() {
				return
			}
			inputPath := strings.TrimSpace(scanner.Text())

			// Читаем шифротекст из файла
			c, err := readCiphertextFile(inputPath)
			if err != nil {
				fmt.Printf("Ошибка чтения шифртекста: %v\n", err)
				continue
			}

			// Расшифровываем шифротекст
			m := Decrypt(priv, c)
			text := BigIntToString(m)

			fmt.Print("Введите путь для сохранения открытого текста: ")
			if !scanner.Scan() {
				return
			}
			outputPath := strings.TrimSpace(scanner.Text())

			// Сохраняем расшифрованное содержимое в файл
			if err := writeTextFile(outputPath, text); err != nil {
				fmt.Printf("Ошибка записи открытого текста: %v\n", err)
				continue
			}

			fmt.Println("Расшифрование файла выполнено")

		// Выход из программы
		case "6":
			fmt.Println("Выход.")
			return

		default:
			fmt.Println("Неверный пункт меню")
		}
	}
}
