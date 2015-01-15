package crypto

import (
	"fmt"
)

const (
	SignatureModeSha256Rsa string = "sha256+rsa"
	SignatureModeSha256Ecdsa string = "sha256+ecdsa"
	HMACMode string = "hmac+sha256"
)

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

func NewHMAC() *Signed {
	return &Signed{Mode: HMACMode}
}

func NewRSASignature() *Signed {
	return &Signed{Mode: SignatureModeSha256Rsa}
}

func NewECDSASignature() *Signed {
	return &Signed{Mode: SignatureModeSha256Ecdsa}
}

func GroupRSAEncrypt(plaintext string, publicKeys map[string]string) (*Encrypted, error) {

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

func GroupECIESEncrypt(plaintext string, publicKeys map[string]string) (*Encrypted, error) {
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
		publicKey, err := PemDecodeECPublic([]byte(publicKeyString))
		if err != nil {
			return nil, err
		}
		encryptedKey, err := ECIESEncrypt(key, publicKey)
		if err != nil {
			return nil, err
		}
		encryptedKeys[id] = string(Base64Encode(encryptedKey))
	}

	return &Encrypted{Ciphertext: string(Base64Encode(ciphertext)), Mode: "aes-cbc-256+ecies", Inputs: inputs,
		Keys: encryptedKeys}, nil
}

func GroupRSADecrypt(encrypted *Encrypted, keyID string, privateKeyPem string) (string, error) {

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

func GroupECIESDecrypt(encrypted *Encrypted, keyID string, privateKeyPem string) (string, error) {
	if encrypted.Mode != "aes-cbc-256+ecies" {
		return "", fmt.Errorf("Invalid mode '%s'", encrypted.Mode)
	}

	if len(privateKeyPem) == 0 {
		return "", fmt.Errorf("Private key pem is 0 bytes")
	}

	ciphertext, _ := Base64Decode([]byte(encrypted.Ciphertext))
	iv, _ := Base64Decode([]byte(encrypted.Inputs["iv"]))
	encryptedKey, _ := Base64Decode([]byte(encrypted.Keys[keyID]))

	privateKey, err := PemDecodeECPrivate([]byte(privateKeyPem))
	if err != nil {
		return "", err
	}

	key, err := ECIESDecrypt(encryptedKey, privateKey)
	if err != nil {
		return "", err
	}

	plaintext, err := AESDecrypt(ciphertext, iv, key)
	return string(plaintext), err
}

func Sign(message string, privateKeyString string, signature *Signed) error {
	var sig []byte
	var err error
	if signature.Mode == SignatureModeSha256Rsa {
		privateKey, _ := PemDecodeRSAPrivate([]byte(privateKeyString))
		sig, err = RSASign([]byte(message), privateKey)
		if err != nil {
			return err
		}
	} else if signature.Mode == SignatureModeSha256Ecdsa {
		privateKey, _ := PemDecodeECPrivate([]byte(privateKeyString))
		sig, err = ECDSASign([]byte(message), privateKey)
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("signature mode %s not supported.", signature.Mode)
	}

	signature.Message = message
	signature.Signature = string(Base64Encode(sig))
	return nil
}

func Verify(signed *Signed, publicKeyString string) error {
	message := []byte(signed.Message)
	signature, _ := Base64Decode([]byte(signed.Signature))
	if signed.Mode == SignatureModeSha256Rsa {
		publicKey, _ := PemDecodeRSAPublic([]byte(publicKeyString))
		return RSAVerify(message, signature, publicKey)
	} else if signed.Mode == SignatureModeSha256Ecdsa {
		publicKey, _ := PemDecodeECPublic([]byte(publicKeyString))
		return ECDSAVerify(message, signature, publicKey)
	} else {
		return fmt.Errorf("signature mode %s not supported.", signed.Mode)
	}

}
