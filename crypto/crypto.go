// ThreatSpec package github.com/pki-io/core/crypto as crypto
package crypto

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
)

// Mode of signature or encryption
type Mode string

// Signature modes
const (
	SignatureModeSha256Rsa   Mode = "sha256+rsa"
	SignatureModeSha256Ecdsa Mode = "sha256+ecdsa"
	SignatureModeSha256Hmac  Mode = "sha256+hmac"
)

// TODO - encryption mode consts

// Encrypted represents a ciphertext with related inputs
type Encrypted struct {
	Ciphertext string
	Mode       string
	Inputs     map[string]string
	Keys       map[string]string
}

// Signed represents a signature and related inputs
type Signed struct {
	Message   string
	Mode      Mode
	Signature string
}

// ThreatSpec TMv0.1 for NewSignature
// Does new signature creation for App:Crypto

// NewSignature returns a new Signed
func NewSignature(mode Mode) *Signed {
	return &Signed{Mode: mode}
}

// ThreatSpec TMv0.1 for GroupEncrypt
// Does hybrid encryption with one or more public keys fore App:Crypto

// GroupEncrypt takes a plaintext and encrypts with one or more public keys.
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

// ThreatSpec TMv0.1 for SymmetricEncrypt
// Does symmetric encryption with a shared key for App:Crypto

// SymmetricEncrypt takes a plaintext and symmetrically encrypts using the given key.
func SymmetricEncrypt(plaintext, id, key string) (*Encrypted, error) {

	rawKey, err := hex.DecodeString(key)
	if err != nil {
		return nil, fmt.Errorf("Could not decode key: %s", err)
	}

	newKey, salt, err := ExpandKey(rawKey, nil)
	if err != nil {
		return nil, fmt.Errorf("Cold not expand key: %s", err)
	}

	ciphertext, iv, err := AESEncrypt([]byte(plaintext), newKey)
	if err != nil {
		return nil, err
	}

	inputs := make(map[string]string)
	inputs["key-id"] = id
	inputs["iv"] = string(Base64Encode(iv))
	inputs["salt"] = string(Base64Encode(salt))

	return &Encrypted{Ciphertext: string(Base64Encode(ciphertext)), Mode: "aes-cbc-256", Inputs: inputs}, nil
}

// ThreatSpec TMv0.1 for GroupDecrypt
// Does hybrid decryption with a private key for App:Crypto

// GroupDecrypt takes an Encrypted struct and decrypts for the given private key, returning a plaintext string.
func GroupDecrypt(encrypted *Encrypted, keyID string, privateKeyPem string) (string, error) {
	var privateKey interface{}
	var err error

	if encrypted.Mode != "aes-cbc-256+rsa" {
		return "", fmt.Errorf("Invalid mode '%s'", encrypted.Mode)
	}

	if len(privateKeyPem) == 0 {
		return "", fmt.Errorf("Private key pem is 0 bytes")
	}

	// TODO - check errors
	ciphertext, _ := Base64Decode([]byte(encrypted.Ciphertext))
	iv, _ := Base64Decode([]byte(encrypted.Inputs["iv"]))
	encryptedKey, _ := Base64Decode([]byte(encrypted.Keys[keyID]))
	privateKey, err = PemDecodePrivate([]byte(privateKeyPem))
	key, err := Decrypt(encryptedKey, privateKey)
	plaintext, err := AESDecrypt(ciphertext, iv, key)
	return string(plaintext), err
}

// ThreatSpec TMv0.1 for SymmetricDecrypt
// Does symmetric decryption with a shared key for App:Crypto

// SymmetricDecrypt takes an Encrypted struct and decrypts with the given symmetric key, returning a plaintext string.
func SymmetricDecrypt(encrypted *Encrypted, key string) (string, error) {
	if encrypted.Mode != "aes-cbc-256" {
		return "", fmt.Errorf("Invalid mode: %s", encrypted.Mode)
	}

	// TODO - check errors
	ciphertext, _ := Base64Decode([]byte(encrypted.Ciphertext))
	iv, _ := Base64Decode([]byte(encrypted.Inputs["iv"]))
	salt, _ := Base64Decode([]byte(encrypted.Inputs["salt"]))

	rawKey, err := hex.DecodeString(key)
	if err != nil {
		return "", fmt.Errorf("Could not decode key: %s", err)
	}

	newKey, _, err := ExpandKey(rawKey, salt)
	if err != nil {
		return "", fmt.Errorf("Cold not expand key: %s", err)
	}

	plaintext, err := AESDecrypt(ciphertext, iv, newKey)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// ThreatSpec TMv0.1 for Sign
// Does message signing for App:Crypto

// Sign takes a message string and signs using the given private key. The signature and inputs are added to the provided Signed input.
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

// ThreatSpec TMv0.1 for Authenticate
// Does message authentication for App:Crypto

// Authenticate takes a message and MACs using the given key. The signature and inputs are added to the provided Signed input.
func Authenticate(message string, key []byte, signature *Signed) error {

	if err := HMAC([]byte(message), key, signature); err != nil {
		return fmt.Errorf("Could not HMAC container: %s", err)
	}

	signature.Mode = SignatureModeSha256Hmac
	return nil
}

// ThreatSpec TMv0.1 for Verify
// Does signature verification for App:Crypto

// Verify takes a Signed struct and verifies the signature using the given key. It supports both symmetric (MAC) and public key signatures.
func Verify(signed *Signed, key []byte) error {
	message := []byte(signed.Message)
	signature, _ := Base64Decode([]byte(signed.Signature))

	if signed.Mode == SignatureModeSha256Hmac {
		return HMACVerify(message, key, signature)
	}

	publicKey, err := PemDecodePublic(key)
	if err != nil {
		return err
	}

	return VerifySignature(message, signature, publicKey)
}
