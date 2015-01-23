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

type KeyType string
const (
	KeyTypeRSA KeyType = "rsa"
	KeyTypeEC KeyType = "ec"
)

func RandomBytes(size int) ([]byte, error) {
	randomBytes := make([]byte, size)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return nil, fmt.Errorf("Could not generate random bytes: %s", err)
	}

	return randomBytes, nil
}

func RandomIntBetween(x, y *big.Int) (*big.Int, error) {
	diff := new(big.Int)
	diff.Sub(y, x)
	r, err := rand.Int(rand.Reader, diff)
	if err != nil {
		return nil, err
	}
	return r.Add(r, x), nil
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

func ExpandKey(key, salt []byte) ([]byte, []byte, error) {
	if len(salt) == 0 {
		var err error
		salt, err = RandomBytes(16) // TODO Shouldn't be hardcoded i guess
		if err != nil {
			return nil, nil, err
		}
	}
	newKey := pbkdf2.Key(key, salt, 100000, 32, sha256.New)
	return newKey, salt, nil
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
	iv, err := RandomBytes(aes.BlockSize)
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

func GenerateRSAKey() (*rsa.PrivateKey, error) {
	if key, err := rsa.GenerateKey(rand.Reader, 2048); err != nil {
		return nil, fmt.Errorf("Can't create RSA keys: %s", err)
	} else {
		return key, nil
	}
}

func GenerateECKey() (*ecdsa.PrivateKey, error) {
	if key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		return nil, fmt.Errorf("Can't create ECDSA keys: %s", err)
	} else {
		return key, nil
	}
}

func PemEncodePrivate(key crypto.PrivateKey) ([]byte, error) {

	switch k := key.(type) {
	case *rsa.PrivateKey:
		der := x509.MarshalPKCS1PrivateKey(k)
		b := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}
		return pem.EncodeToMemory(b), nil
	case *ecdsa.PrivateKey:
		if der, err := x509.MarshalECPrivateKey(k); err != nil {
			return nil, fmt.Errorf("Can't marshal ECDSA key: %s", err)
		} else {
			b := &pem.Block{Type: "ECDSA PRIVATE KEY", Bytes: der}
			return pem.EncodeToMemory(b), nil
		}
	default:
		return nil, errors.New("Unsupported private key type")
	}

}

// TODO: These PEM Encode functions should probably return a string, since everywhere (so far) that these are being used
// TODO: Are converting them anyway...
func PemEncodePublic(key crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, err
	}

	var t string
	switch key.(type) {
	case *rsa.PublicKey:
		t = "RSA PUBLIC KEY"
	case *ecdsa.PublicKey:
		t = "ECDSA PUBLIC KEY"
	default:
		return nil, errors.New("Unsupported public key type")
	}

	b := &pem.Block{Type: t, Bytes: der}
	return pem.EncodeToMemory(b), nil
}

func PemDecodePrivate(in []byte) (crypto.PrivateKey, error) {
	b, _ := pem.Decode(in)
	if key, err := x509.ParsePKCS1PrivateKey(b.Bytes); err != nil {
		if eckey, err := x509.ParseECPrivateKey(b.Bytes); err != nil {
			return nil, fmt.Errorf("Could not parse private key: %s", err)
		} else {
			return eckey, nil
		}
	} else {
		return key, nil
	}
}

func PemDecodePublic(in []byte) (crypto.PublicKey, error) {
	b, _ := pem.Decode(in)
	if pubKey, err := x509.ParsePKIXPublicKey(b.Bytes); err != nil {
		return nil, fmt.Errorf("Could not parse public key: %s", err.Error())
	} else {
		return pubKey, nil
	}
}

func Encrypt(plaintext []byte, publicKey crypto.PublicKey) ([]byte, error) {
	switch k := publicKey.(type) {
	case *rsa.PublicKey:
		return rsaEncrypt(plaintext, k)
	case *ecdsa.PublicKey:
		return eciesEncrypt(plaintext, k)
	default:
		return nil, errors.New("Unsupporte public key type")
	}
}

func rsaEncrypt(plaintext []byte, publicKey *rsa.PublicKey) ([]byte, error) {
	label := []byte("")
	hash := sha256.New()
	if ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, publicKey, plaintext, label); err != nil {
		return nil, fmt.Errorf("Could not RSA encrypt: %s", err.Error())
	} else {
		return ciphertext, nil
	}
}

func eciesEncrypt(plaintext []byte, publicKey *ecdsa.PublicKey) ([]byte, error) {
	n := publicKey.Curve.Params().N
	r, err := RandomIntBetween(big.NewInt(1), n)
	if err != nil {
		return nil, err
	}

	i := r.Bytes()
	if err != nil {
		return nil, err
	}
	elliptic.P256()
	rx, ry := publicKey.Curve.ScalarBaseMult(i)
	px, _ := publicKey.Curve.ScalarMult(publicKey.X, publicKey.Y, i)
	k, err := deriveEciesKey(px.Bytes(), 32)
	if err != nil {
		return nil, err
	}
	ke := k[:16]
	km := k[16:]

	cipherText, iv, err := AESEncrypt(plaintext, ke)
	if err != nil {
		return nil, err
	}

	macTag := hmac256(km, cipherText)

	buf := bytes.NewBuffer(make([]byte, 0))

	buf.WriteByte(byte(len(rx.Bytes())))
	buf.Write(rx.Bytes())
	buf.WriteByte(byte(len(ry.Bytes())))
	buf.Write(ry.Bytes())
	buf.Write(iv)
	buf.Write(macTag)
	buf.Write(cipherText)

	return buf.Bytes(), nil
}

func deriveEciesKey(rawSecret []byte, outputKeyLength int32) ([]byte, error) {
	var maxOutputLength int32 =  3200
	var hmacSha256ByteLength int32 = 32

	if outputKeyLength > maxOutputLength {
		return nil, errors.New(fmt.Sprintf("Output key length is too large. Max is %d", maxOutputLength))
	}
	var n int32
	if outputKeyLength%hmacSha256ByteLength == 0 {
		n = outputKeyLength/hmacSha256ByteLength
	} else {
		n = outputKeyLength/hmacSha256ByteLength+1
	}
	results := make([]byte, (n+1)*hmacSha256ByteLength)
	tmpDgst := make([]byte, hmacSha256ByteLength)
	tmpMsg := make([]byte, 32+1+4)

	for i := byte(1); i <= byte(n); i++ {
		copy(tmpMsg, []byte{i, 0x00, 32, byte(outputKeyLength*8)})
		if numCopied := copy(tmpDgst, hmac256(rawSecret, tmpMsg)); int32(numCopied) < hmacSha256ByteLength {
			return nil, errors.New("Error while producing hmac.")
		}
		var j int32 = 0
		for k := (i-1)*byte(hmacSha256ByteLength); k < i*byte(hmacSha256ByteLength); k++ {
			results[k] = tmpDgst[j]
			j++
		}
	}

	return results[outputKeyLength:], nil
}

func Decrypt(cipherText []byte, privateKey crypto.PrivateKey) ([]byte, error) {
	switch k := privateKey.(type) {
	case *rsa.PrivateKey:
		return rsaDecrypt(cipherText, k)
	case *ecdsa.PrivateKey:
		return eciesDecrypt(cipherText, k)
	default:
		return nil, errors.New("Unsupported private key type")
	}
}

func rsaDecrypt(ciphertext []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	label := []byte("")
	hash := sha256.New()
	if plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, privateKey, ciphertext, label); err != nil {
		return nil, fmt.Errorf("Could not RSA decrypt: %s", err.Error())
	} else {
		return plaintext, nil
	}
}

func ExtractMacTag(ciphertext []byte) []byte {
	rxEnd := ciphertext[0] + 1
	ryEnd := rxEnd + 1 + ciphertext[rxEnd]
	return ciphertext[ryEnd+16:ryEnd+48]
}

func eciesDecrypt(cipherText []byte, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	rx := new(big.Int)
	ry := new(big.Int)
	rxEnd := cipherText[0] + 1
	rx.SetBytes(cipherText[1:rxEnd])
	ryEnd := rxEnd + 1 + cipherText[rxEnd]
	ry.SetBytes(cipherText[rxEnd+1: ryEnd])
	iv := cipherText[ryEnd:ryEnd+16]
	macTag := cipherText[ryEnd+16:ryEnd+48]
	encryptedMessage := cipherText[ryEnd+48:]
	keyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	s, _ := elliptic.P256().ScalarMult(rx, ry, keyBytes)

	k, err := deriveEciesKey(s.Bytes(), 32)
	if err != nil {
		return nil, err
	}
	ke := k[:16]
	km := k[16:]
	mac := hmac256(km, encryptedMessage)
	if !hmac.Equal(mac, macTag) {
		return nil, errors.New("Macs do not match.")
	}

	return AESDecrypt(encryptedMessage, iv, ke)
}

func SignMessage(message []byte, privateKey crypto.PrivateKey) ([]byte, error) {
	switch k := privateKey.(type) {
	case *rsa.PrivateKey:
		return rsaSign(message, k)
	case *ecdsa.PrivateKey:
		return ecdsaSign(message, k)
	default:
		return nil, errors.New("Unsupported private key type.")
	}
}

func rsaSign(message []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
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

func ecdsaSign(message[]byte, privateKey *ecdsa.PrivateKey) ([]byte, error) {
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

func VerifySignature(message []byte, signature []byte, publicKey crypto.PublicKey) error {
	switch k := publicKey.(type) {
	case *rsa.PublicKey:
		return rsaVerify(message, signature, k)
	case *ecdsa.PublicKey:
		return ecdsaVerify(message, signature, k)
	default:
		return errors.New("Unsupported public key type.")
	}
}

func rsaVerify(message []byte, signature []byte, publicKey *rsa.PublicKey) error {
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

func ecdsaVerify(message []byte, signature []byte , publicKey *ecdsa.PublicKey) error {
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

func hmac256(message, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)

	return mac.Sum(nil)
}

// Should really be moved into Sign method then case on mode (with nice consts)
func HMAC(message []byte, key []byte, signature *Signed) error {
	mac := hmac256(message, key)
	signature.Message = string(message)
	signature.Mode = HMACMode
	signature.Signature = string(Base64Encode(mac))
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
