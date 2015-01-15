package crypto

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"io"
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"
	"errors"
)

// https://www.socketloop.com/tutorials/golang-padding-un-padding-data
// https://www.socketloop.com/tutorials/golang-example-for-rsa-package-functions-example

func RandomBytes(size int) (randomBytes []byte) {
	randomBytes = make([]byte, size)
	_, err := rand.Read(randomBytes)
	if err != nil {
		panic(fmt.Errorf("Could not generate random bytes: %s", err.Error()))
	} else {
		return randomBytes
	}
}

func Pad(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func UnPad(src []byte) []byte {
	length := len(src)
	unpadding := int(src[length-1])
	return src[:(length - unpadding)]
}

func ExpandKey(key []byte) ([]byte, []byte) {
	salt := RandomBytes(16) // TODO Shouldn't be hardcoded i guess
	newKey := pbkdf2.Key(key, salt, 100000, 32, sha256.New)
	return newKey, salt
}

func Base64Encode(input []byte) []byte {
	return []byte(base64.StdEncoding.EncodeToString(input))
}

func Base64Decode(input []byte) (decoded []byte, err error) {
	b, err := base64.StdEncoding.DecodeString(string(input))
	if err != nil {
		return nil, fmt.Errorf("Can't Base64 decode: %s", err.Error())
	} else {
		return []byte(b), nil
	}
}

func AESEncrypt(plaintext []byte, key []byte) ([]byte, []byte, error) {
	if len(plaintext) == 0 {
		return nil, nil, fmt.Errorf("Plaintext can't be empty")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("Can't initialise cipher: %s", err.Error())
	}

	paddedPlaintext := Pad(plaintext, aes.BlockSize)
	ciphertext := make([]byte, len(paddedPlaintext))
	iv := RandomBytes(aes.BlockSize)

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, paddedPlaintext)

	return ciphertext, iv, nil
}

func AESDecrypt(ciphertext []byte, iv []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("Can't initialise cipher: %s", err.Error())
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext is not a multiple of the block size")
	}

	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("iv is not equal to block size")
	}

	paddedPlaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(paddedPlaintext, ciphertext)

	return UnPad(paddedPlaintext), nil
}

func GenerateRSAKey() *rsa.PrivateKey {
	if key, err := rsa.GenerateKey(rand.Reader, 2048); err != nil {
		panic(fmt.Sprintf("Can't create RSA keys: %s", err.Error()))
	} else {
		return key
	}
}

func GenerateECKey() *ecdsa.PrivateKey {
	if key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		panic(fmt.Sprintf("Can't create ECDSA keys: %s", err))
	} else {
		return key
	}
}

func PemEncodeRSAPrivate(key *rsa.PrivateKey) []byte {
	der := x509.MarshalPKCS1PrivateKey(key)
	b := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}
	return pem.EncodeToMemory(b)
}

func PemEncodeECPrivate(key *ecdsa.PrivateKey) []byte {
	if der, err := x509.MarshalECPrivateKey(key); err != nil {
		panic(fmt.Sprintf("Can't marshal ECDSA key: %s", err))
	} else {
		b := &pem.Block{Type: "ECDSA PRIVATE KEY", Bytes: der}
		return pem.EncodeToMemory(b)
	}
}

func PemEncodeRSAPublic(key *rsa.PublicKey) []byte {
	der, _ := x509.MarshalPKIXPublicKey(key)
	b := &pem.Block{Type: "RSA PUBLIC KEY", Bytes: der}
	return pem.EncodeToMemory(b)
}

func PemEncodeECPublic(key *ecdsa.PublicKey) []byte {
	if der, err := x509.MarshalPKIXPublicKey(key); err != nil {
		panic(fmt.Sprintf("Can't marshal ec public key: %s", err))
	} else {
		b := &pem.Block{Type: "ECDSA PUBLIC KEY", Bytes: der}
		return pem.EncodeToMemory(b)
	}
}

func PemDecodeRSAPrivate(in []byte) (*rsa.PrivateKey, error) {
	b, _ := pem.Decode(in)
	if key, err := x509.ParsePKCS1PrivateKey(b.Bytes); err != nil {
		return nil, fmt.Errorf("Could not parse private key: %s", err.Error())
	} else {
		return key, nil
	}
}

func PemDecodeECPrivate(in []byte) (*ecdsa.PrivateKey, error) {
	b, _ := pem.Decode(in)
	if key, err := x509.ParseECPrivateKey(b.Bytes); err != nil {
		return nil, fmt.Errorf("Could not parse private key: %s", err)
	} else {
		return key, nil
	}
}

func PemDecodeRSAPublic(in []byte) (*rsa.PublicKey, error) {
	b, _ := pem.Decode(in)
	if pubKey, err := x509.ParsePKIXPublicKey(b.Bytes); err != nil {
		return nil, fmt.Errorf("Could not parse public key: %s", err.Error())
	} else {
		return pubKey.(*rsa.PublicKey), nil
	}
}

func PemDecodeECPublic(in []byte) (*ecdsa.PublicKey, error) {
	b, _ := pem.Decode(in)
	if pub, err := x509.ParsePKIXPublicKey(b.Bytes); err != nil {
		return nil, fmt.Errorf("Could not parse public key: %s", err)
	} else {
		return pub.(*ecdsa.PublicKey), nil
	}
}

func RSAEncrypt(plaintext []byte, publicKey *rsa.PublicKey) ([]byte, error) {
	label := []byte("")
	hash := sha256.New()
	if ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, publicKey, plaintext, label); err != nil {
		return nil, fmt.Errorf("Could not RSA encrypt: %s", err.Error())
	} else {
		return ciphertext, nil
	}
}

func ECIESEncrypt(plaintext []byte, publicKey *ecdsa.PublicKey) ([]byte, error) {
	// TODO: implement
	return nil, nil
}

func RSADecrypt(ciphertext []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	label := []byte("")
	hash := sha256.New()
	if plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, privateKey, ciphertext, label); err != nil {
		return nil, fmt.Errorf("Could not RSA decrypt: %s", err.Error())
	} else {
		return plaintext, nil
	}
}

func ECIESDecrypt(ciphertext []byte, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	// TODO: implement
	return nil, nil
}

func RSASign(message []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	var h crypto.Hash
	hash := sha256.New()
	io.WriteString(hash, string(message))
	hashed := hash.Sum(nil)
	if signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, h, hashed); err != nil {
		return nil, fmt.Errorf("Could not RSA sign: %s", err.Error())
	} else {
		return signature, nil
	}
}

func ECDSASign(message[]byte, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	hash := sha256.New()
	io.WriteString(hash, string(message))
	hashed := hash.Sum(nil)
	if r, s, err := ecdsa.Sign(rand.Reader, privateKey, hashed); err != nil {
		return nil, fmt.Errorf("Could not ECDSA sign: %s", err)
	} else {

		buf := new(bytes.Buffer)
		buf.Write([]byte{byte(len(r.Bytes()))})
		buf.Write(r.Bytes())
		buf.Write(s.Bytes())

		return buf.Bytes(), nil
	}
}

func RSAVerify(message []byte, signature []byte, publicKey *rsa.PublicKey) error {
	var h crypto.Hash
	hash := sha256.New()
	io.WriteString(hash, string(message))
	hashed := hash.Sum(nil)
	if err := rsa.VerifyPKCS1v15(publicKey, h, hashed, signature); err != nil {
		return fmt.Errorf("Could not RSA verify: %s", err.Error())
	} else {
		return nil
	}
}

func ECDSAVerify(message []byte, signature []byte , publicKey *ecdsa.PublicKey) error {
	hash := sha256.New()
	io.WriteString(hash, string(message))
	hashed := hash.Sum(nil)
	l := int(signature[0])
	r := new(big.Int).SetBytes(signature[1:l+1])
	s := new(big.Int).SetBytes(signature[l+1:])
	if ok := ecdsa.Verify(publicKey, hashed, r, s); !ok {
		return errors.New("Could not ECDSA verify.")
	} else {
		return nil
	}
}

// Should really be moved into Sign method then case on mode (with nice consts)
func HMAC(message []byte, key []byte, signature *Signed) error {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	finalMAC := mac.Sum(nil)
	signature.Message = string(message)
	signature.Mode = HMACMode
	signature.Signature = string(Base64Encode(finalMAC))
	return nil
}

func HMACVerify(message, key []byte, signature *Signed) error {
	newMac := hmac.New(sha256.New, key)
	newMac.Write(message)
	newFinalMac := newMac.Sum(nil)

	oldMac, err := Base64Decode([]byte(signature.Signature))
	if err != nil {
		return fmt.Errorf("Could not base64 decode mac: %s", err.Error())
	}

	if hmac.Equal(newFinalMac, oldMac) {
		return nil
	} else {
		return fmt.Errorf("MACs not equal")
	}
}
