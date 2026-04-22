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
	DefaultKeyBits    = 12
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

func extendedGCD(a, b *big.Int) (g, x, y *big.Int) {
	// Инициализация: x=0, y=1, x1=1, y1=0
	x0, y0, x1, y1 := new(big.Int), new(big.Int), new(big.Int), new(big.Int)
	x1.SetInt64(1) // x1 = 1
	y0.SetInt64(1) // y0 = 1 (было неявно 0)

	for b.Cmp(big.NewInt(0)) != 0 {
		q := new(big.Int).Div(a, b) // q = a/b
		// x2 = x0 - q*x1
		t := new(big.Int).Mul(q, x1)
		x2 := new(big.Int).Sub(x0, t)
		// y2 = y0 - q*y1
		t = new(big.Int).Mul(q, y1)
		y2 := new(big.Int).Sub(y0, t)

		// Сдвиг
		x0, x1 = x1, x2
		y0, y1 = y1, y2
		a, b = b, new(big.Int).Mod(a, b)
	}

	return a, x0, y0 // gcd=a, x=x0, y=y0
}

func modInverse(e, phi *big.Int) *big.Int {
	// Возвращает d такое, что e*d ≡ 1 (mod phi)
	_, x, _ := extendedGCD(e, phi)
	// x может быть отрицательным → приводим к [0, φ(n))
	return new(big.Int).Mod(x, phi)
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
		if q == p {
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
		// 1/65537 шанс — просто перегенерировать p, q (2 секунды)
		return generateKeyPair()
	}
	d := modInverse(DefaultE, phi) //Экспонента расшифрования
	return &PublicKey{E: DefaultE, N: n}, &PrivateKey{D: d, N: n}, nil
}

func main() {
	fmt.Println("RSA Key Generator")
	fmt.Printf("Key size: %d bits\n", DefaultKeyBits)

	pub, priv, err := generateKeyPair()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("Открытый ключ:\n  e = %s\n  n = %s\n",
		pub.E.String(), pub.N.String())
	fmt.Printf("Закрытый ключ:\n  d = %s\n  n = %s\n",
		priv.D.String(), priv.N.String())
}
