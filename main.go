package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

type PublicKey struct {
	N *big.Int // модуль n = p * q
	E *big.Int // открытая экспонента e (обычно 65537)
}

type PrivateKey struct {
	N *big.Int // тот же модуль n
	D *big.Int // закрытая экспонента d = e^(-1) mod φ(n)
}

type KeyPair struct {
	Public  *PublicKey  // открытый ключ
	Private *PrivateKey // закрытый ключ
}

var DefaultE = big.NewInt(65537) //Экспонента зашифрования по дефолту

// Проверка на четность
func isEven(n *big.Int) bool {
	return n.Bit(0) == 0
}

const (
	MillerRabinRounds = 20
	DefaultKeyBits    = 2048
)

// --------------------------
// генерирайция случайного нечетного числа точно заданной битности для использования в качестве кандидата на простое число в RSA.
// --------------------------
func randomNumberGen(bits int) (*big.Int, error) {
	//верхняя граница случайного числа
	limit := new(big.Int).Lsh(big.NewInt(1), uint(bits))
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, err
	}
	// Установить старший бит, чтобы число точно было нужной битности
	// на случай что сгенерировалось меньше
	n.SetBit(n, bits-1, 1)

	// Установить младший бит, чтобы число было нечетным
	n.SetBit(n, 0, 1)
	return n, nil
}

// Вероятностная проверка простоты по Миллеру–Рабину
func isProbablyPrime(n *big.Int, rounds int) bool {
	one := big.NewInt(1)
	two := big.NewInt(2)
	three := big.NewInt(3)
	zero := big.NewInt(0)

	// Простые базовые случаи
	if n.Cmp(two) == 0 || n.Cmp(three) == 0 {
		return true
	}
	if n.Cmp(two) < 0 || isEven(n) {
		return false
	}

	// Представим n - 1 как 2^s * d, где d нечетное
	nMinusOne := new(big.Int).Sub(n, one)
	d := new(big.Int).Set(nMinusOne)
	s := 0

	for d.Bit(0) == 0 {
		d.Rsh(d, 1)
		s++
	}

	// rounds раундов теста
	for i := 0; i < rounds; i++ {
		// Случайное a в диапазоне [2, n-2]
		max := new(big.Int).Sub(n, big.NewInt(3))
		a, err := rand.Int(rand.Reader, max)
		if err != nil {
			return false
		}
		a.Add(a, two)

		// x = a^d mod n
		x := new(big.Int).Exp(a, d, n)

		if x.Cmp(one) == 0 || x.Cmp(nMinusOne) == 0 {
			continue
		}

		composite := true
		for r := 1; r < s; r++ {
			x.Exp(x, two, n)

			if x.Cmp(nMinusOne) == 0 {
				composite = false
				break
			}
			if x.Cmp(zero) == 0 {
				return false
			}
		}

		if composite {
			return false
		}
	}

	return true
}

func generatePrime(bits int, rounds int) (*big.Int, error) {
	for {
		candidate, err := randomNumberGen(bits)
		if err != nil {
			return nil, err
		}

		if isProbablyPrime(candidate, rounds) {
			return candidate, nil
		}
	}
}

func extendedEvklid(e, phi *big.Int) (x *big.Int) {
	x0, y0, x1, y1 := new(big.Int), new(big.Int), new(big.Int), new(big.Int)
	x0.SetInt64(1) // x0 = 1
	x1.SetInt64(0) // x1 = 0
	y0.SetInt64(0) // y0 = 0
	y1.SetInt64(1) // y1 = 1
	a := new(big.Int).Set(e)
	b := new(big.Int).Set(phi)
	for b.Cmp(big.NewInt(0)) != 0 {
		q := new(big.Int).Div(a, b) // q = a/b
		r := new(big.Int).Mod(a, b)
		x2 := new(big.Int).Sub(x0, new(big.Int).Mul(q, x1))
		y2 := new(big.Int).Sub(y0, new(big.Int).Mul(q, y1))
		a = b
		b = r
		x0, x1 = x1, x2
		y0, y1 = y1, y2
	}
	return new(big.Int).Set(x0)
}

func generateKeyPair() (*PublicKey, *PrivateKey, error) {
	p, err := generatePrime(DefaultKeyBits/2, MillerRabinRounds) //DefaultKeyBits/2 чтобы выровнять нагрузку
	if err != nil {
		return nil, nil, err
	}
	q, err := generatePrime(DefaultKeyBits/2, MillerRabinRounds)
	if err != nil {
		return nil, nil, err
	}
	for {
		if q.Cmp(p) == 0 {
			q, err = generatePrime(DefaultKeyBits/2, MillerRabinRounds)
			if err != nil {
				return nil, nil, err
			}
		} else {
			break
		}
	}
	n := new(big.Int).Mul(p, q)
	phi := new(big.Int).Mul( //расчёт значения функции Эйлера
		new(big.Int).Sub(p, big.NewInt(1)),
		new(big.Int).Sub(q, big.NewInt(1)),
	)
	if new(big.Int).GCD(nil, nil, DefaultE, phi).Cmp(big.NewInt(1)) != 0 { //если нет взаимной простоты, делаем перегенерацию
		return generateKeyPair()
	}
	d := new(big.Int).Mod(extendedEvklid(DefaultE, phi), phi)
	return &PublicKey{E: DefaultE, N: n}, &PrivateKey{D: d, N: n}, nil
}

func encrypt(pub *PublicKey, message *big.Int) *big.Int {
	if message.Cmp(pub.N) >= 0 {
		panic("Сообщение слишком большое! M < n")
	}
	return new(big.Int).Exp(message, pub.E, pub.N)
}

func decrypt(priv *PrivateKey, ciphertext *big.Int) *big.Int {
	return new(big.Int).Exp(ciphertext, priv.D, priv.N)
}

func stringToBigInt(s string) *big.Int {
	return new(big.Int).SetBytes([]byte(s))
}

func bigIntToString(n *big.Int) string {
	return string(n.Bytes())
}

func main() {
	fmt.Printf("Размер RSA ключа: %d bits\n", DefaultKeyBits)

	pub, priv, err := generateKeyPair()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("Открытый ключ:\n  e = %s\n  n = %s\n",
		pub.E.String(), pub.N.String())
	fmt.Printf("Закрытый ключ:\n  d = %s\n  n = %s\n",
		priv.D.String(), priv.N.String())

	message := stringToBigInt("Test")
	fmt.Printf("Сообщение: '%s'\n", bigIntToString(message))

	// Шифрование
	ciphertext := encrypt(pub, message)
	fmt.Printf("Шифротекст: %s\n", ciphertext.String())

	// Расшифрование
	decrypted := decrypt(priv, ciphertext)
	fmt.Printf("Расшифровано: '%s'\n", bigIntToString(decrypted))

	// Проверка
	if message.Cmp(decrypted) == 0 {
		fmt.Println("работает")
	} else {
		fmt.Println("ошибка")
	}

}
