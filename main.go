package main

import (
	"go_security/hashing"
	"log"
	"runtime"
)


func main() {
	p := &hashing.ArgonParams{
		Memory: 64 * 1024,
		Iterations: 1,
		Parallelism: uint8(runtime.NumCPU()),
		SaltLength: 16,
		KeyLength: 32,
	};

	log.SetFlags(log.LstdFlags | log.Lshortfile)

	encodedHash, err := p.GenEncodedHash("pass")
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Encoded hash with salt: %v", encodedHash)

	// this changes the values in p to what are in encodedHash (if you are decoding some another encoded hash)
	match, err := p.VerifyPassword("pass", encodedHash)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("\nVerification: %v\n", match)
}
