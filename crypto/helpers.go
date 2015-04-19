package crypto

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/pki-io/ecies"
	"golang.org/x/crypto/pbkdf2"
	"io"
	"math/big"
	"time"
)

// https://www.socketloop.com/tutorials/golang-example-for-rsa-package-functions-example

// KeyType represents a supported public key pair type
type KeyType string

// Key types
const (
	KeyTypeRSA KeyType = "rsa"
	KeyTypeEC  KeyType = "ec"
)

// TimeOrderedUUID taken directly from https://github.com/mitchellh/packer/blob/master/common/uuid/uuid.go
func TimeOrderedUUID() string {
	unix := uint32(time.Now().UTC().Unix())

	b := make([]byte, 12)
	n, err := rand.Read(b)
	if n != len(b) {
		err = fmt.Errorf("Not enough entropy available")
	}
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%04x%08x",
		unix, b[0:2], b[2:4], b[4:6], b[6:8], b[8:])
}

// UUID is an opinionated helper function that generate a 128 bit time-ordered UUID string.
//
// Documentation for the TimeOrderedUUID function is available here:
// TODO
//
// From the source docs: Top 32 bits are a timestamp, bottom 96 bytes are random.
func UUID() string {
	return TimeOrderedUUID()
}

// ThreatSpec TMv0.1 for RandomBytes
// Mitigates cryptography against Use of Insufficiently Random Values (CWE-330) with standard package which uses secure implementation

// RandomBytes generates and returns size number of random bytes.
func RandomBytes(size int) ([]byte, error) {
	randomBytes := make([]byte, size)
	numBytesRead, err := rand.Read(randomBytes)
	if err != nil {
		return nil, fmt.Errorf("Could not generate random bytes: %s", err)
	}

	if numBytesRead != size {
		return nil, fmt.Errorf("Wrong number of random bytes read: %i vs %i", size, numBytesRead)
	}

	return randomBytes, nil
}

// Pad takes the src byte array and PKCS5 pads it to blockSize, returning the padded byte array.
//
// Taken from the tutorial available here:
// https://www.socketloop.com/tutorials/golang-padding-un-padding-data
func Pad(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

// UnPad takes the src byte array and PKCS5 unpads it.
//
// Taken from the tutorial available here:
// https://www.socketloop.com/tutorials/golang-padding-un-padding-data
func UnPad(src []byte) []byte {
	length := len(src)
	unpadding := int(src[length-1])
	return src[:(length - unpadding)]
}

// ThreatSpec TMv0.1 for ExpandKey
// Mitigates cryptography against Use of Password Hash With Insufficient Computational Effort (CWE-916) with PBKDF2 provided by standard package
// Mitigates cryptography against Use of a One-Way Hash without a Salt (CWE-759) with salt create by function
// Mitigates cryptography against Use of a One-Way Hash with a Predictable Salt (CWE-760) with salt created with good PRNG

// ExpandKey is an opinionated helper function to cryptographically expand a key using a 128 bit salt and PBKDF2.
// If the salt is of 0 length, it generates a new salt, and returns the expanded key and salt as byte arrays.
//
// A salt should only be provided as part of a decryption or verification process. When using ExpandKey to create a new key, let ExpandKey generate the salt. This is to lessen the risk of a weak or non-unique salt being used.
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

// Base64Encode returns the base64 encoding of the input.
func Base64Encode(input []byte) []byte {
	return []byte(base64.StdEncoding.EncodeToString(input))
}

// Base64Decode returns the base64 decoded input.
func Base64Decode(input []byte) (decoded []byte, err error) {
	b, err := base64.StdEncoding.DecodeString(string(input))
	if err != nil {
		return nil, fmt.Errorf("Can't Base64 decode: %s", err)
	}
	return []byte(b), nil
}

// ThreatSpec TMv0.1 for AESEncrypt
// Mitigates cryptography against weak cipher with strong encryption cipher in CBC mode
// Mitigates cryptography against weak cipher with sufficient key size
// Mitigates cryptography against failure to use a random IV in CBC mode with generated random IV

// AESEncrypt is an opinionated helper function that implements 256 bit AES in CBC mode.
// It creates a random 128 bit IV which is returned along with the ciphertext.
func AESEncrypt(plaintext, key []byte) (ciphertext []byte, iv []byte, err error) {
	if len(plaintext) == 0 {
		return nil, nil, fmt.Errorf("Plaintext can't be empty")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("Can't initialise cipher: %s", err)
	}

	paddedPlaintext := Pad(plaintext, aes.BlockSize)
	ciphertext = make([]byte, len(paddedPlaintext))
	iv, err = RandomBytes(aes.BlockSize)
	if err != nil {
		return nil, nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, paddedPlaintext)

	return ciphertext, iv, nil
}

// AESDecrypt is an opinionated helper function that decryptes a ciphertext encrypted
// with 256 bit AES in CBC mode and returns the plaintext.
func AESDecrypt(ciphertext, iv, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("Can't initialise cipher: %s", err)
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

// ThreatSpec TMv0.1 for GenerateRSAKey
// Mitigates cryptography against weak private key with RSA key generated using standard package
// Mitigates cryptography against weak private key with sufficient RSa key size of 2048 bits

// GenerateRSAKey is an opinionated helper function to generate a 2048 bit RSA key pair
func GenerateRSAKey() (*rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("Can't create RSA keys: %s", err)
	}
	return key, nil
}

// ThreatSpec TMv0.1 for GenerateECKey
// Exposes cryptography to weak private key with EC key generated by third-party package

// GenerateECKey is an opinionated helper function to generate a P256 ECDSA key pair.
func GenerateECKey() (*ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("Can't create ECDSA keys: %s", err)
	}
	return key, nil
}

// PemEncodePrivate PEM encodes a private key. It supports RSA and ECDSA key types.
func PemEncodePrivate(key crypto.PrivateKey) ([]byte, error) {

	switch k := key.(type) {
	case *rsa.PrivateKey:
		der := x509.MarshalPKCS1PrivateKey(k)
		b := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}
		return pem.EncodeToMemory(b), nil
	case *ecdsa.PrivateKey:
		der, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, fmt.Errorf("Can't marshal ECDSA key: %s", err)
		}
		b := &pem.Block{Type: "ECDSA PRIVATE KEY", Bytes: der}
		return pem.EncodeToMemory(b), nil
	default:
		return nil, errors.New("Unsupported private key type")
	}

}

// PemEncodePublic PEM encodes a public key. It supports RSA and ECDSA.
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

// PemDecodePrivate decodes a PEM encoded private key. It supports PKCS1 and EC private keys.
func PemDecodePrivate(in []byte) (crypto.PrivateKey, error) {
	b, _ := pem.Decode(in)
	key, err := x509.ParsePKCS1PrivateKey(b.Bytes)
	if err != nil {
		eckey, err := x509.ParseECPrivateKey(b.Bytes)
		if err != nil {
			return nil, fmt.Errorf("Could not parse private key: %s", err)
		}
		return eckey, nil
	}
	return key, nil
}

// PemDecodePublic decodes a PEM encoded public key. It supports any PKIX public key.
func PemDecodePublic(in []byte) (crypto.PublicKey, error) {
	b, _ := pem.Decode(in)
	pubKey, err := x509.ParsePKIXPublicKey(b.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Could not parse public key: %s", err)
	}
	return pubKey, nil
}

// Encrypt is a wrapper function that will encrypt a plaintext using the provided public key,
// and returns the ciphertext. It supports RSA and ECDSA public keys.
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

// ThreatSpec TMv0.1 for rsaEncrypt
// Mitigates cryptography against Use of RSA Algorithm without OAEP (CWE-780) with RSA encryption using OAEP with SHA-256

// rsaEncrypt is an opinionated helper function that encryptes a plaintext using an RSA public key,
// and returns the ciphertext. It uses OAEP with SHA-256.
func rsaEncrypt(plaintext []byte, publicKey *rsa.PublicKey) ([]byte, error) {
	label := []byte("")
	hash := sha256.New()
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, publicKey, plaintext, label)
	if err != nil {
		return nil, fmt.Errorf("Could not RSA encrypt: %s", err)
	}
	return ciphertext, nil
}

// ThreatSpec TMv0.1 for eciesEncrypt
// Mitigates cryptography against something else with Elliptic Curve Integrated Encryption Scheme
// Exposes cryptography to something bleh with encryption performed by third-party package

// eciesEncrypt is an opinionated helper function that encryptes a plaintext using an EC DSA public key,
// and returns the ciphertext.
//
// It uses ecies (integrated encryption scheme) provided by an external library, documentation of which is available here:
// https://github.com/obscuren/ecies
func eciesEncrypt(plaintext []byte, publicKey *ecdsa.PublicKey) ([]byte, error) {
	pub := ecies.ImportECDSAPublic(publicKey)
	return ecies.Encrypt(rand.Reader, pub, plaintext, nil, nil)
}

// Decrypt is a wrapper function that will decrypt a ciphertext using the provided private key,
// and returns the plaintext. It supports RSA and ECDSA private keys.
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

// rsaDecrypt is an opinionated helper function that decryptes a ciphertext using an RSA private key.
// It uses OAEP with SHA-256.
func rsaDecrypt(ciphertext []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	label := []byte("")
	hash := sha256.New()
	plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, privateKey, ciphertext, label)
	if err != nil {
		return nil, fmt.Errorf("Could not RSA decrypt: %s", err)
	}
	return plaintext, nil
}

// eciesDecrypt is an opinionated helper function that decryptes a ciphertext using an ECDSA private key.
//
// it uses ecies (integrated encryption scheme) provided by an external library, documentation of which is available here:
// https://github.com/obscuren/ecies
func eciesDecrypt(cipherText []byte, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	pri := ecies.ImportECDSA(privateKey)
	return pri.Decrypt(rand.Reader, cipherText, nil, nil)
}

// SignMessage signs a message using the provided private key. It supports RSA and ECDSA and returns the message signature.
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

// rsaSign is an opinionated helper function that signs a message using an RSA private key. It uses PKCS1v15 with SHA-256, and returns the message signature.
func rsaSign(message []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	var h crypto.Hash
	hash := sha256.New()
	_, err := io.WriteString(hash, string(message))
	if err != nil {
		return nil, fmt.Errorf("Could not write to hash: %s", err)
	}

	hashed := hash.Sum(nil)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, h, hashed)
	if err != nil {
		return nil, fmt.Errorf("Could not RSA sign: %s", err)
	}
	return signature, nil
}

// ecdsaSign is an opinionated helper function that signs a message using an ECDSA private key, and returns the message signature. It uses SHA-256 for hashing.
func ecdsaSign(message []byte, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	hash := sha256.New()
	_, err := io.WriteString(hash, string(message))
	if err != nil {
		return nil, fmt.Errorf("Could not write to hash: %s", err)
	}

	hashed := hash.Sum(nil)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hashed)
	if err != nil {
		return nil, fmt.Errorf("Could not ECDSA sign: %s", err)
	}

	// TODO - this bit is ugly
	buf := new(bytes.Buffer)
	_, err = buf.Write([]byte{byte(len(r.Bytes()))})
	if err != nil {
		return nil, fmt.Errorf("Could not write to buffer: %s", err)
	}
	_, err = buf.Write(r.Bytes())
	if err != nil {
		return nil, fmt.Errorf("Could not write to buffer: %s", err)
	}
	_, err = buf.Write(s.Bytes())
	if err != nil {
		return nil, fmt.Errorf("Could not write to buffer: %s", err)
	}

	return buf.Bytes(), nil
}

// VerifySignature verifies a message for a given signature and public key. If verified, the function returns nil, otherwise it returns an error. It supports RSA and ECDSA public keys.
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

// rsaVerify is an opinionated helper function that verifies a message for a given signature and RSA public key. If verified, the function returns nil, otherwise it returns an error. It uses PKCS1v15 with SHA-256.
func rsaVerify(message []byte, signature []byte, publicKey *rsa.PublicKey) error {
	var h crypto.Hash
	hash := sha256.New()
	_, err := io.WriteString(hash, string(message))
	if err != nil {
		return fmt.Errorf("Could not write to hash: %s", err)
	}

	hashed := hash.Sum(nil)
	err = rsa.VerifyPKCS1v15(publicKey, h, hashed, signature)
	if err != nil {
		return fmt.Errorf("Could not RSA verify: %s", err)
	}
	return nil
}

// ecdsaVerify is an opinionated helper function that verifies a message for a given signature and ECDSA public key. If verified, the function returns nil, otherwise it returns an error. It uses SHA-256 for hashing.
func ecdsaVerify(message []byte, signature []byte, publicKey *ecdsa.PublicKey) error {
	hash := sha256.New()
	_, err := io.WriteString(hash, string(message))
	if err != nil {
		return fmt.Errorf("Could not write to hash: %s", err)
	}

	hashed := hash.Sum(nil)
	l := int(signature[0])
	r := new(big.Int).SetBytes(signature[1 : l+1])
	s := new(big.Int).SetBytes(signature[l+1:])
	ok := ecdsa.Verify(publicKey, hashed, r, s)
	if !ok {
		return errors.New("Could not ECDSA verify.")
	}
	return nil
}

// hmac256 is an opinionated helper function that generates a HMAC for the given message using SHA-256.
func hmac256(message, key []byte) ([]byte, error) {
	mac := hmac.New(sha256.New, key)
	_, err := mac.Write(message)
	if err != nil {
		return nil, fmt.Errorf("Could not write to mac: %s", err)
	}

	return mac.Sum(nil), nil
}

// HMAC is a wrapper function that calculates a HMAC for a given message and symmetric key.
func HMAC(message []byte, key []byte, signature *Signed) error {
	mac, err := hmac256(message, key)
	if err != nil {
		return fmt.Errorf("Could not get mac: %s", err)
	}

	signature.Message = string(message)
	signature.Signature = string(Base64Encode(mac))
	return nil
}

// ThreatSpec TMv0.1 for HMACVerify
// Mitigates cryptography against side-channel attack with use of time-constant comparison provided by standard package

// HMACVerify verifies the HMAC of the given message. If verified, the function returns nil, otherwise it returns an error.
func HMACVerify(message, key, signature []byte) error {
	newMac := hmac.New(sha256.New, key)
	_, err := newMac.Write(message)
	if err != nil {
		return fmt.Errorf("Could not write to mac: %s", err)
	}

	newFinalMac := newMac.Sum(nil)

	if hmac.Equal(newFinalMac, signature) {
		return nil
	}
	return fmt.Errorf("MACs not equal")
}
