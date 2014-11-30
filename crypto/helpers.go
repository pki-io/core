package crypto

import (
    "fmt"
    "bytes"
    "io"
    "encoding/base64"
    "crypto"
    "crypto/rand"
    "crypto/cipher"
    "crypto/rsa"
    "crypto/aes"
    "crypto/sha256"
    "crypto/x509"
    "encoding/pem"
)

// https://www.socketloop.com/tutorials/golang-padding-un-padding-data
// https://www.socketloop.com/tutorials/golang-example-for-rsa-package-functions-example

func RandomBytes(size int) ([]byte) {
    randomBytes := make([]byte, size)
    _, err := rand.Read(randomBytes)
    if err != nil {
        panic(fmt.Errorf("Could not generate random bytes: %s",err.Error()))
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

func Base64Encode(input []byte) ([]byte) {
    return []byte(base64.StdEncoding.EncodeToString(input))
}

func Base64Decode(input []byte) ([]byte, error) {
    b, err := base64.StdEncoding.DecodeString(string(input))
    return []byte(b), err
}

func AESEncrypt(plaintext []byte, key []byte) ([]byte, []byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, nil, err
    }
    paddedPlaintext := Pad(plaintext, aes.BlockSize)
    ciphertext := make([]byte, len(paddedPlaintext))
    iv := RandomBytes(aes.BlockSize)
    if err != nil {
        return nil, nil, err
    }

    mode := cipher.NewCBCEncrypter(block, iv)
    mode.CryptBlocks(ciphertext, paddedPlaintext)

    return ciphertext, iv, nil
}

func AESDecrypt(ciphertext []byte, iv []byte, key []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    if len(ciphertext) % aes.BlockSize != 0 {
        return nil, fmt.Errorf("ciphertext is not a multiple of the block size")
    }

    if len(iv) != aes.BlockSize {
        return nil, fmt.Errorf("iv is wrong size")
    }

    paddedPlaintext := make([]byte, len(ciphertext))
    mode := cipher.NewCBCDecrypter(block, iv)
    mode.CryptBlocks(paddedPlaintext, ciphertext)

    return UnPad(paddedPlaintext), nil
}

func GenerateRSAKey() (*rsa.PrivateKey, error) {
    return rsa.GenerateKey(rand.Reader, 2048)
}

func PemEncodeRSAPrivate(key *rsa.PrivateKey) ([]byte) {
    der := x509.MarshalPKCS1PrivateKey(key)
    b := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}
    return pem.EncodeToMemory(b)
}

func PemEncodeRSAPublic(key *rsa.PublicKey) ([]byte) {
    der, _ := x509.MarshalPKIXPublicKey(key)
    b := &pem.Block{Type: "RSA PUBLIC KEY", Bytes: der}
    return pem.EncodeToMemory(b)
}

func PemDecodeRSAPrivate(in []byte) (*rsa.PrivateKey, error) {
    b, _ := pem.Decode(in)
    return x509.ParsePKCS1PrivateKey(b.Bytes)
}

func PemDecodeRSAPublic(in []byte) (*rsa.PublicKey, error) {
    b, _ := pem.Decode(in)
    pubKey, err := x509.ParsePKIXPublicKey(b.Bytes)
    return pubKey.(*rsa.PublicKey), err
}

func RSAEncrypt(plaintext []byte, publicKey *rsa.PublicKey) ([]byte, error) {
    label := []byte("")
    hash := sha256.New()
    return rsa.EncryptOAEP(hash, rand.Reader, publicKey, plaintext, label)
}

func RSADecrypt(ciphertext []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
    label := []byte("")
    hash := sha256.New()
    return rsa.DecryptOAEP(hash, rand.Reader, privateKey, ciphertext, label)
}

func RSASign(message []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
    var h crypto.Hash
    hash := sha256.New()
    io.WriteString(hash, string(message))
    hashed := hash.Sum(nil)
    return rsa.SignPKCS1v15(rand.Reader, privateKey, h, hashed)
}

func RSAVerify(message []byte, signature []byte, publicKey *rsa.PublicKey) (bool, error) {
    var h crypto.Hash
    hash := sha256.New()
    io.WriteString(hash, string(message))
    hashed := hash.Sum(nil)
    if err := rsa.VerifyPKCS1v15(publicKey, h, hashed, signature); err != nil {
      return false, err
    } else {
      return true, nil
    }
}
