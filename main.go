package main

import (
	"crypto/rand"
	"fmt"

	"./zed"
)

func rng(n int) []byte {
	var b = make([]byte, n)
	rand.Read(b)
	return b
}

func hex(s []byte) string {
	return fmt.Sprintf("%x", s)
}

func echo(label string, value interface{}) {
	fmt.Println(label, value)
}

func testSign(fuckup bool) {
	// var hash = sha256.New()

	fmt.Println("\nTEST SIGNING: should validate =", !fuckup)

	var seed = rng(32)
	echo("  seed       :", hex(seed[:]))

	var secret = zed.SecretFromSeed(seed[:])
	var secretKey = secret.Key()
	echo("  secret     :", hex(secretKey[:]))

	var public = secret.Public()
	var publicKey = public.Key()
	echo("  public     :", hex(publicKey[:]))

	var message = rng(16)
	echo("  message    :", hex(message[:]))

	var sig = secret.Sign(message[:])
	echo("  signature  :", hex(sig[:]))

	if fuckup {
		var r = rng(2)
		if r[1] == 0 {
			r[1] = 1
		}
		message[int(r[0])%len(message)] += r[1]
		echo("  msg-fucked :", hex(message[:]))
	}

	var valid = public.Verify(message[:], sig[:])
	echo("  valid?     :", valid)

	echo("  test passed:", (valid != fuckup))

	fmt.Println("")
}

//
//
//
func main() {
	for i := 0; i < 10; i++ {
		testSign(false)
		testSign(true)
	}
}
