package main

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strconv"
)

// Private keys are stored as PKCS#8. When a passphrase is supplied we wrap the
// PKCS#8 DER in a custom PEM block encrypted with AES-256-GCM, using a key
// derived from the passphrase with PBKDF2-SHA256. Everything here is standard
// library (crypto/pbkdf2 landed in Go 1.24).
const (
	plainKeyType = "PRIVATE KEY"
	encKeyType   = "NETANCHOR ENCRYPTED KEY"
	pbkdf2Iter   = 600_000
	saltLen      = 16
)

var errPassphraseRequired = errors.New("this key is passphrase-protected; please provide the passphrase")

// marshalKey serializes a signer to PEM, encrypting it when passphrase != "".
func marshalKey(key crypto.Signer, passphrase string) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	if passphrase == "" {
		return pem.EncodeToMemory(&pem.Block{Type: plainKeyType, Bytes: der}), nil
	}

	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	gcm, err := gcmFromPassphrase(passphrase, salt, pbkdf2Iter)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, der, nil)

	body := make([]byte, 0, len(salt)+len(nonce)+len(ciphertext))
	body = append(body, salt...)
	body = append(body, nonce...)
	body = append(body, ciphertext...)

	return pem.EncodeToMemory(&pem.Block{
		Type: encKeyType,
		Headers: map[string]string{
			"KDF":        "PBKDF2-SHA256",
			"Iterations": strconv.Itoa(pbkdf2Iter),
			"Cipher":     "AES-256-GCM",
		},
		Bytes: body,
	}), nil
}

// unmarshalKey parses a PEM private key, transparently decrypting it if it is a
// passphrase-protected block.
func unmarshalKey(pemBytes []byte, passphrase string) (crypto.Signer, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("invalid private key PEM")
	}

	der := block.Bytes
	if block.Type == encKeyType {
		if passphrase == "" {
			return nil, errPassphraseRequired
		}
		var err error
		if der, err = decryptKey(block, passphrase); err != nil {
			return nil, err
		}
	}

	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("key is not a usable signer")
	}
	return signer, nil
}

func decryptKey(block *pem.Block, passphrase string) ([]byte, error) {
	iter, err := strconv.Atoi(block.Headers["Iterations"])
	if err != nil || iter <= 0 {
		iter = pbkdf2Iter
	}
	gcm, err := gcmFromPassphrase(passphrase, blockSalt(block), iter)
	if err != nil {
		return nil, err
	}
	body := block.Bytes
	if len(body) < saltLen+gcm.NonceSize() {
		return nil, errors.New("encrypted key is malformed")
	}
	nonce := body[saltLen : saltLen+gcm.NonceSize()]
	ciphertext := body[saltLen+gcm.NonceSize():]

	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.New("could not decrypt key (wrong passphrase?)")
	}
	return plain, nil
}

func blockSalt(block *pem.Block) []byte {
	if len(block.Bytes) < saltLen {
		return nil
	}
	return block.Bytes[:saltLen]
}

func gcmFromPassphrase(passphrase string, salt []byte, iter int) (cipher.AEAD, error) {
	dk, err := pbkdf2.Key(sha256.New, passphrase, salt, iter, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(dk)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// isEncryptedKeyPEM reports whether a stored key is passphrase-protected.
func isEncryptedKeyPEM(pemBytes []byte) bool {
	block, _ := pem.Decode(pemBytes)
	return block != nil && block.Type == encKeyType
}
