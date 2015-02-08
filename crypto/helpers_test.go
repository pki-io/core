package crypto

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

func TestRandomBytes(t *testing.T) {
	size := 10
	random, err := RandomBytes(size)
	assert.NoError(t, err)
	assert.Equal(t, size, len(random), "they should be equal")
}

func TestPad(t *testing.T) {
	size := 10
	msg := []byte("012345")
	padded := Pad(msg, size)
	assert.Equal(t, len(padded), size, "short input should be padded")

	msg = []byte("0123456789")
	padded = Pad(msg, size)
	expectedSize := size * 2
	assert.Equal(t, len(padded), expectedSize, "full block of padding")
}

func TestUnpad(t *testing.T) {
	size := 10
	expectedSize := 5
	padded := []byte{1, 2, 3, 4, 5, 5, 5, 5, 5, 5}
	assert.Equal(t, len(padded), size, "padding size is correct")
	msg := UnPad(padded)
	assert.Equal(t, len(msg), expectedSize)
}

func TestBase64Encode(t *testing.T) {
	in := []byte("an input")
	expectedOut := []byte("YW4gaW5wdXQ=") // echo -n "an input" | base64
	out := Base64Encode(in)
	assert.Equal(t, out, expectedOut, "output should match")
}

func TestBase64Decode(t *testing.T) {
	in := []byte("YW4gaW5wdXQ=") // echo -n "an input" | base64
	expectedOut := []byte("an input")
	out, err := Base64Decode(in)
	assert.Nil(t, err)
	assert.Equal(t, out, expectedOut, "output should match")
}

func TestAESEncrypt(t *testing.T) {
	plaintext := []byte("secret message")
	key, _ := RandomBytes(32)
	ciphertext, iv, err := AESEncrypt(plaintext, key)
	assert.Nil(t, err)
	assert.NotNil(t, ciphertext)
	assert.NotNil(t, iv)
}

func TestAESDecrypt(t *testing.T) {
	plaintext := []byte("secret message")
	key, _ := RandomBytes(32)
	ciphertext, iv, err := AESEncrypt(plaintext, key)
	newPlaintext, err := AESDecrypt(ciphertext, iv, key)
	assert.Nil(t, err)
	assert.Equal(t, string(plaintext), string(newPlaintext), "new plaintext must equal old plaintext")
}

func TestGenerateRSAKey(t *testing.T) {
	key, err := GenerateRSAKey()
	assert.NoError(t, err)
	assert.NotNil(t, key.D)
}

func TestGenerateECKey(t *testing.T) {
	key, err := GenerateECKey()
	assert.NoError(t, err)
	assert.NotNil(t, key.D)
}

func TestPemEncodePrivate(t *testing.T) {
	rsakey, _ := GenerateRSAKey()
	eckey, _ := GenerateECKey()
	pemKey, err := PemEncodePrivate(rsakey)
	assert.NoError(t, err)
	assert.NotNil(t, pemKey)
	assert.Equal(t, strings.Contains(string(pemKey), "RSA PRIVATE KEY"), true)

	pemKey, err = PemEncodePrivate(eckey)
	assert.NoError(t, err)
	assert.NotNil(t, pemKey)
	assert.Equal(t, strings.Contains(string(pemKey), "ECDSA PRIVATE KEY"), true)
}

func TestPemDecodePrivate(t *testing.T) {
	rsakey, _ := GenerateRSAKey()
	eckey, _ := GenerateECKey()
	pemKey, _ := PemEncodePrivate(rsakey)
	newKey, err := PemDecodePrivate(pemKey)
	assert.NoError(t, err)
	assert.Equal(t, rsakey, newKey)

	pemKey, _ = PemEncodePrivate(eckey)
	newKey, err = PemDecodePrivate(pemKey)
	assert.NoError(t, err)
	assert.Equal(t, eckey, newKey)
}

func TestPemEncodePublic(t *testing.T) {
	rsakey, _ := GenerateRSAKey()
	eckey, _ := GenerateECKey()

	pemKey, err := PemEncodePublic(&rsakey.PublicKey)
	assert.NoError(t, err)
	assert.NotNil(t, pemKey)
	assert.Equal(t, strings.Contains(string(pemKey), "RSA PUBLIC KEY"), true)

	pemKey, err = PemEncodePublic(&eckey.PublicKey)
	assert.NoError(t, err)
	assert.NotNil(t, pemKey)
	assert.Equal(t, strings.Contains(string(pemKey), "ECDSA PUBLIC KEY"), true)
}

func TestPemDecodePublic(t *testing.T) {
	rsakey, _ := GenerateRSAKey()
	eckey, _ := GenerateECKey()

	pemKey, _ := PemEncodePublic(&rsakey.PublicKey)
	newKey, err := PemDecodePublic(pemKey)
	assert.NoError(t, err)
	assert.Equal(t, rsakey.N, newKey.(*rsa.PublicKey).N)

	pemKey, _ = PemEncodePublic(&eckey.PublicKey)
	newKey, err = PemDecodePublic(pemKey)
	assert.NoError(t, err)
	assert.Equal(t, eckey.Curve, newKey.(*ecdsa.PublicKey).Curve)
}

func TestEncrypt(t *testing.T) {
	plaintext, _ := RandomBytes(32)
	rsakey, _ := GenerateRSAKey()
	eckey, _ := GenerateECKey()

	ciphertext, err := Encrypt(plaintext, &rsakey.PublicKey)
	assert.NoError(t, err)
	assert.NotNil(t, ciphertext)

	ciphertext, err = Encrypt(plaintext, &eckey.PublicKey)
	assert.NoError(t, err)
	assert.NotNil(t, ciphertext)
}

func TestDecrypt(t *testing.T) {
	plaintext, _ := RandomBytes(32)
	rsakey, _ := GenerateRSAKey()
	eckey, _ := GenerateECKey()

	ciphertext, _ := Encrypt(plaintext, &rsakey.PublicKey)
	newPlaintext, err := Decrypt(ciphertext, rsakey)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, newPlaintext)

	ciphertext, _ = Encrypt(plaintext, &eckey.PublicKey)
	newPlaintext, err = Decrypt(ciphertext, eckey)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, newPlaintext)
}

func TestSignMessage(t *testing.T) {
	message := []byte("this is a message")
	rsakey, _ := GenerateRSAKey()
	eckey, _ := GenerateECKey()

	sig, err := SignMessage(message, rsakey)
	assert.NoError(t, err)
	assert.NotNil(t, sig)

	sig, err = SignMessage(message, eckey)
	assert.NoError(t, err)
	assert.NotNil(t, sig)
}

func TestVerifySignature(t *testing.T) {
	message := []byte("this is a message")
	rsakey, _ := GenerateRSAKey()
	eckey, _ := GenerateECKey()

	sig, _ := SignMessage(message, rsakey)
	err := VerifySignature(message, sig, &rsakey.PublicKey)
	assert.NoError(t, err)

	sig, _ = SignMessage(message, eckey)
	err = VerifySignature(message, sig, &eckey.PublicKey)
	assert.NoError(t, err)
}

func TestHMACHelper(t *testing.T) {
	mac := NewHMAC()
	message := "message to be authenticated"
	key, _ := RandomBytes(32)
	HMAC([]byte(message), key, mac)
	assert.Equal(t, mac.Message, message)
	assert.NotEqual(t, mac.Signature, "")
}

func TestHMACVerifyHelper(t *testing.T) {
	mac := NewHMAC()
	message := "message to be authenticated"
	key, _ := RandomBytes(32)

	HMAC([]byte(message), key, mac)

	err := HMACVerify([]byte(message), key, mac)
	assert.Nil(t, err)
}

func TestExpandKeyHelper(t *testing.T) {
	key, _ := RandomBytes(16)
	newKey, salt, err := ExpandKey(key, nil)
	assert.NoError(t, err)
	assert.Equal(t, len(salt), 16)
	assert.Equal(t, len(newKey), 32)
}

func TestExpandKeyHelperWithSalt(t *testing.T) {
	key, _ := RandomBytes(16)
	salt, _ := RandomBytes(16)
	newKey, newSalt, err := ExpandKey(key, salt)
	assert.NoError(t, err)
	assert.Equal(t, salt, newSalt)
	assert.Equal(t, len(newKey), 32)
}
