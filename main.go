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
		fmt.Println("6. Демонстрационный режим")
		fmt.Println("7. Выход")
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

		// Демонстрационный режим — шифрование малых чисел с отображением всех шагов RSA
		case "6":
			// Пользователь вводит p, q, e и сообщение вручную
			if !scanner.Scan() {
				return
			}
			// Ввод простого числа p
			pStr := strings.TrimSpace(scanner.Text())
			p, ok := new(big.Int).SetString(pStr, 10)
			if !ok || p.Cmp(big.NewInt(2)) < 0 {
				fmt.Println("Некорректное число p")
				continue
			}

			// Ввод простого числа q
			fmt.Print("Введите q: ")
			if !scanner.Scan() {
				return
			}
			// Ввод простого числа q
			qStr := strings.TrimSpace(scanner.Text())
			q, ok := new(big.Int).SetString(qStr, 10)
			if !ok || q.Cmp(big.NewInt(2)) < 0 {
				fmt.Println("Некорректное число q")
				continue
			}

			// Проверка: p и q должны быть различными
			if p.Cmp(q) == 0 {
				fmt.Println("p и q не должны совпадать")
				continue
			}

			// Ввод открытой экспоненты e
			fmt.Print("Введите e: ")
			if !scanner.Scan() {
				return
			}
			eStr := strings.TrimSpace(scanner.Text())
			e, ok := new(big.Int).SetString(eStr, 10)
			if !ok || e.Cmp(big.NewInt(2)) < 0 {
				fmt.Println("Некорректное число e")
				continue
			}

			// Вычисление φ(n) = (p-1) * (q-1)
			one := big.NewInt(1)
			pMinus1 := new(big.Int).Sub(p, one)
			qMinus1 := new(big.Int).Sub(q, one)
			phi := new(big.Int).Mul(pMinus1, qMinus1)

			// Проверка: NOK(e, φ(n)) = 1
			gcd := new(big.Int).GCD(nil, nil, e, phi)
			if gcd.Cmp(big.NewInt(1)) != 0 {
				fmt.Println("e должно быть взаимно простым с phi(n)")
				continue
			}

			// Вычисление n = p * q
			n := new(big.Int).Mul(p, q)
			// Вычисление закрытой экспоненты d = e^(-1) mod φ(n)
			d := new(big.Int).Mod(extendedEvklid(e, phi), phi)
			if d.Sign() < 0 {
				d.Add(d, phi)
			}

			// Формирование структуры открытого ключа
			pub := &PublicKey{
				N: new(big.Int).Set(n),
				E: new(big.Int).Set(e),
			}

			// Формирование структуры закрытого ключа
			priv := &PrivateKey{
				N: new(big.Int).Set(n),
				D: new(big.Int).Set(d),
				P: new(big.Int).Set(p),
				Q: new(big.Int).Set(q),
				E: new(big.Int).Set(e),
			}

			// Ввод сообщения (число или ASCII-символ)
			fmt.Print("Введите один ASCII-символ или число для шифрования: ")
			if !scanner.Scan() {
				return
			}
			input := strings.TrimSpace(scanner.Text())

			// Преобразование ввода в big.Int
			var m *big.Int

			// Если введён число — используем его напрямую
			if num, ok := new(big.Int).SetString(input, 10); ok {
				m = num
			} else {
				// Иначе интерпретируем как ASCII-символ
				runes := []rune(input)
				if len(runes) != 1 {
					fmt.Println("Нужно ввести либо одно число, либо ровно один символ")
					continue
				}
				if runes[0] > 127 {
					fmt.Println("Нужно ввести ASCII-символ")
					continue
				}
				m = big.NewInt(int64(runes[0]))
			}

			// Проверка: сообщение должно быть меньше модуля n
			if m.Cmp(n) >= 0 {
				fmt.Println("Сообщение должно быть меньше n")
				continue
			}

			// Шифрование: C = M^e mod n
			c := Encrypt(pub, m)
			// Расшифрование: M' = C^d mod n
			decrypted := Decrypt(priv, c)

			// Вывод всех шагов RSA-алгоритма
			fmt.Println("=== Демонстрационный режим RSA ===")
			fmt.Printf("p = %s\n", p.String())
			fmt.Printf("q = %s\n", q.String())
			fmt.Printf("n = p * q = %s\n", n.String())
			fmt.Printf("phi(n) = (p - 1) * (q - 1) = %s\n", phi.String())
			fmt.Printf("e = %s\n", e.String())
			fmt.Printf("d = %s\n", d.String())
			fmt.Printf("M = %s\n", m.String())
			fmt.Printf("C = M^e mod n = %s\n", c.String())
			fmt.Printf("M' = C^d mod n = %s\n", decrypted.String())

			// Проверка корректности расшифрования
			if decrypted.Cmp(m) == 0 {
				fmt.Println("Расшифрование успешно")
			} else {
				fmt.Println("Ошибка: расшифрованное значение не совпало с исходным")
			}

			// Вывод расшифрованного значения как ASCII-символа
			if decrypted.Cmp(big.NewInt(128)) < 0 {
				fmt.Printf("Как ASCII-символ: %q\n", rune(decrypted.Int64()))
			}

		// Выход из программы
		case "7":
			fmt.Println("Выход.")
			return

		default:
			fmt.Println("Неверный пункт меню")
		}
	}
}
