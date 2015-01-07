package crypto

import (
	"fmt"
)

const SignatureMode string = "sha256+rsa"

type Encrypted struct {
	Ciphertext string
	Mode       string
	Inputs     map[string]string
	Keys       map[string]string
}

type Signed struct {
	Message string
	Mode    string
	//Inputs map[string]string
	Signature string
}

func NewSignature() *Signed {
	return &Signed{Mode: SignatureMode}
}

func GroupEncrypt(plaintext string, publicKeys map[string]string) (*Encrypted, error) {

	keySize := 32
	key := RandomBytes(keySize)
	ciphertext, iv, err := AESEncrypt([]byte(plaintext), key)
	if err != nil {
		return nil, err
	}
	inputs := make(map[string]string)
	inputs["iv"] = string(Base64Encode(iv))

	encryptedKeys := make(map[string]string)
	for id, publicKeyString := range publicKeys {
		publicKey, err := PemDecodeRSAPublic([]byte(publicKeyString))
		encryptedKey, err := RSAEncrypt(key, publicKey)
		if err != nil {
			return nil, err
		}
		encryptedKeys[id] = string(Base64Encode(encryptedKey))
	}

	return &Encrypted{Ciphertext: string(Base64Encode(ciphertext)), Mode: "aes-cbc-256+rsa", Inputs: inputs, Keys: encryptedKeys}, nil
}

func GroupDecrypt(encrypted *Encrypted, keyID string, privateKeyPem string) (string, error) {

	if encrypted.Mode != "aes-cbc-256+rsa" {
		return "", fmt.Errorf("Invalid mode '%s'", encrypted.Mode)
	}

	if len(privateKeyPem) == 0 {
		return "", fmt.Errorf("Private key pem is 0 bytes")
	}

	ciphertext, _ := Base64Decode([]byte(encrypted.Ciphertext))
	iv, _ := Base64Decode([]byte(encrypted.Inputs["iv"]))
	encryptedKey, _ := Base64Decode([]byte(encrypted.Keys[keyID]))

	privateKey, err := PemDecodeRSAPrivate([]byte(privateKeyPem))
	key, err := RSADecrypt(encryptedKey, privateKey)

	plaintext, err := AESDecrypt(ciphertext, iv, key)
	return string(plaintext), err
}

func Sign(message string, privateKeyString string, signature *Signed) error {
	privateKey, _ := PemDecodeRSAPrivate([]byte(privateKeyString))
	sig, err := RSASign([]byte(message), privateKey)
	if err != nil {
		return err
	} else {
		signature.Message = message
		signature.Mode = SignatureMode
		signature.Signature = string(Base64Encode(sig))
		return nil
	}
}

func Verify(signed *Signed, publicKeyString string) error {
	publicKey, _ := PemDecodeRSAPublic([]byte(publicKeyString))
	message := []byte(signed.Message)
	signature, _ := Base64Decode([]byte(signed.Signature))
	return RSAVerify(message, signature, publicKey)
}
