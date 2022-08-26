package hashing

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"runtime"
	"strings"

	"golang.org/x/crypto/argon2"
)

type ArgonParams struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

func(p* ArgonParams) GenEncodedHash(password string) (encodedHash string, err error) {
	salt, err := generateRandomBytes(p.SaltLength)
	if err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(password), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)

	/* b64salt := base64.RawStdEncoding.EncodeToString(salt)
	b64hash := base64.RawStdEncoding.EncodeToString(hash) */

	encodedHash = fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, p.Memory, p.Iterations, p.Parallelism, hash, salt)

	return encodedHash, nil
}

func generateRandomBytes(saltLen uint32) ([]byte, error) {
	b := make([]byte, saltLen)
	_, err := rand.Read(b)  // use crypto/rand
	if err != nil {
		return nil, err
	}

	return b, nil
}

func(p* ArgonParams) decodeHash(encodedStr string) (salt, hash[] byte, err error) {
	vals := strings.Split(encodedStr, "$")
	if len(vals) != 6 {
		return nil, nil, errors.New(fmt.Sprintf("the encoded hash is not in correct format, len: %d", len(vals)))
	}

	var version int
	_, err = fmt.Sscanf(vals[2], "v=%d", &version)
	if err != nil {
		return nil, nil, err
	}

	if version != argon2.Version {
		return nil, nil, errors.New(
			fmt.Sprintf("Version incompatible. Decoded version: %d, current version: %d", version, argon2.Version))
	}

	_, err = fmt.Sscanf(vals[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Iterations, &p.Parallelism)
	if err != nil {
		return nil, nil, err
	}

	salt, err = base64.RawURLEncoding.Strict().DecodeString(vals[5])
	if err != nil {
		_, file, line, _ := runtime.Caller(1)
		return nil, nil, errors.New(fmt.Sprintf("[error] %s:%d %v", file, line, err))
	}
	p.SaltLength = uint32(len(salt))

	hash, err = base64.RawStdEncoding.Strict().DecodeString(vals[4])
	if err != nil {
		_, file, line, _ := runtime.Caller(1)
		return nil, nil, errors.New(fmt.Sprintf("[error] %s:%d %v", file, line, err))
	}
	p.KeyLength = uint32(len(hash))

	return salt, hash, nil
}

func(p* ArgonParams) VerifyPassword(password, encodedHash string) (match bool, err error) {
	salt, hash, err := p.decodeHash(encodedHash)
	if err != nil {
		return false, err
	}

	newHash := argon2.IDKey([]byte(password), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)

	if subtle.ConstantTimeCompare(hash, newHash) == 1 {
		return true, nil
	}

	return false, nil
}
