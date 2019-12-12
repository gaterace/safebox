// based on https://github.com/SimonWaldherr/golang-examples/blob/master/advanced/aesgcm.go

package cryptutil

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
)

func AesGcmEncrypt(key []byte, plaintext []byte) ([]byte, error) {
	invalidParameterError := errors.New("invalid parameters")

	if (len(key) != 32) || (len(plaintext) == 0) {
		return nil, invalidParameterError
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// fmt.Printf("nonce: %x\n", nonce)

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)

	// fmt.Printf("ciphertext: %x\n", ciphertext)

	noncelen := len(nonce)
	cipherlen := len(ciphertext)

	buf := make([]byte, noncelen+cipherlen)
	for k := 0; k < noncelen; k++ {
		buf[k] = nonce[k]
	}

	for k := 0; k < cipherlen; k++ {
		buf[k+noncelen] = ciphertext[k]
	}

	return buf, nil
}

func AesGcmDecrypt(key []byte, ciphertext []byte) ([]byte, error) {

	invalidParameterError := errors.New("invalid parameters")
	noncelen := 12

	if (len(key) != 32) || (len(ciphertext) < noncelen) {
		return nil, invalidParameterError
	}

	nonce := ciphertext[0:noncelen]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext[noncelen:], nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func AesKeyFromPassPhrase(phrase string) []byte {
	sha := sha256.Sum256([]byte(phrase))

	key := make([]byte, 32)
	for k := 0; k < 32; k++ {
		key[k] = sha[k]
	}
	return []byte(key)
}
