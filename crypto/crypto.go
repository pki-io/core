package crypto

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
)

type Mode string

const (
	SignatureModeSha256Rsa   Mode = "sha256+rsa"
	SignatureModeSha256Ecdsa Mode = "sha256+ecdsa"
	HMACMode                 Mode = "hmac+sha256"
)

type Encrypted struct {
	Ciphertext string
	Mode       string
	Inputs     map[string]string
	Keys       map[string]string
}

type Signed struct {
	Message string
	Mode    Mode
	//Inputs map[string]string
	Signature string
}

func NewHMAC() *Signed {
	return &Signed{Mode: HMACMode}
}

func NewSignature(mode Mode) *Signed {
	return &Signed{Mode: mode}
}

func GroupEncrypt(plaintext string, publicKeys map[string]string) (*Encrypted, error) {

	keySize := 32
	key, err := RandomBytes(keySize)
	if err != nil {
		return nil, err
	}
	ciphertext, iv, err := AESEncrypt([]byte(plaintext), key)
	if err != nil {
		return nil, err
	}
	inputs := make(map[string]string)
	inputs["iv"] = string(Base64Encode(iv))

	encryptedKeys := make(map[string]string)
	for id, publicKeyString := range publicKeys {
		publicKey, err := PemDecodePublic([]byte(publicKeyString))
		encryptedKey, err := Encrypt(key, publicKey)
		if err != nil {
			return nil, err
		}
		encryptedKeys[id] = string(Base64Encode(encryptedKey))
	}

	return &Encrypted{Ciphertext: string(Base64Encode(ciphertext)), Mode: "aes-cbc-256+rsa", Inputs: inputs, Keys: encryptedKeys}, nil
}

func GroupDecrypt(encrypted *Encrypted, keyID string, privateKeyPem string) (string, error) {
	var privateKey interface{}
	var err error

	if encrypted.Mode != "aes-cbc-256+rsa" {
		return "", fmt.Errorf("Invalid mode '%s'", encrypted.Mode)
	}

	if len(privateKeyPem) == 0 {
		return "", fmt.Errorf("Private key pem is 0 bytes")
	}

	ciphertext, _ := Base64Decode([]byte(encrypted.Ciphertext))
	iv, _ := Base64Decode([]byte(encrypted.Inputs["iv"]))
	encryptedKey, _ := Base64Decode([]byte(encrypted.Keys[keyID]))
	privateKey, err = PemDecodePrivate([]byte(privateKeyPem))
	key, err := Decrypt(encryptedKey, privateKey)
	plaintext, err := AESDecrypt(ciphertext, iv, key)
	return string(plaintext), err
}

func Sign(message string, privateKeyString string, signature *Signed) error {
	privateKey, err := PemDecodePrivate([]byte(privateKeyString))
	if err != nil {
		return err
	}

	switch privateKey.(type) {
	case *rsa.PrivateKey:
		signature.Mode = SignatureModeSha256Rsa
	case *ecdsa.PrivateKey:
		signature.Mode = SignatureModeSha256Ecdsa
	}
	sig, err := SignMessage([]byte(message), privateKey)
	if err != nil {
		return err
	}

	signature.Message = message
	signature.Signature = string(Base64Encode(sig))
	return nil
}

func Verify(signed *Signed, publicKeyString string) error {
	message := []byte(signed.Message)
	signature, _ := Base64Decode([]byte(signed.Signature))
	publicKey, err := PemDecodePublic([]byte(publicKeyString))
	if err != nil {
		return err
	}

	return VerifySignature(message, signature, publicKey)
}
