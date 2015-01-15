package crypto

import (
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

func TestRandomBytes(t *testing.T) {
	size := 10
	random := RandomBytes(size)
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
	key := RandomBytes(32)
	ciphertext, iv, err := AESEncrypt(plaintext, key)
	assert.Nil(t, err)
	assert.NotNil(t, ciphertext)
	assert.NotNil(t, iv)
}

func TestAESDecrypt(t *testing.T) {
	plaintext := []byte("secret message")
	key := RandomBytes(32)
	ciphertext, iv, err := AESEncrypt(plaintext, key)
	newPlaintext, err := AESDecrypt(ciphertext, iv, key)
	assert.Nil(t, err)
	assert.Equal(t, string(plaintext), string(newPlaintext), "new plaintext must equal old plaintext")
}

func TestGenerateRSAKey(t *testing.T) {
	key := GenerateRSAKey()
	assert.NotNil(t, key.D)
}

func TestPemEncodeRSAPrivate(t *testing.T) {
	key := GenerateRSAKey()
	pemKey := PemEncodeRSAPrivate(key)
	assert.NotNil(t, pemKey)
	assert.Equal(t, strings.Contains(string(pemKey), "RSA PRIVATE KEY"), true)
}

func TestPemDecodeRSAPrivate(t *testing.T) {
	key := GenerateRSAKey()
	pemKey := PemEncodeRSAPrivate(key)
	newKey, err := PemDecodeRSAPrivate(pemKey)
	assert.Nil(t, err)
	assert.Equal(t, key, newKey)
}

func TestPemEncodeRSAPublic(t *testing.T) {
	key := GenerateRSAKey()
	pemKey := PemEncodeRSAPublic(&key.PublicKey)
	assert.NotNil(t, pemKey)
	assert.Equal(t, strings.Contains(string(pemKey), "RSA PUBLIC KEY"), true)
}

func TestPemDecodeRSAPublic(t *testing.T) {
	key := GenerateRSAKey()
	pemKey := PemEncodeRSAPublic(&key.PublicKey)
	newKey, err := PemDecodeRSAPublic(pemKey)
	assert.Nil(t, err)
	assert.Equal(t, key.N, newKey.N)
}

func TestRSAEncrypt(t *testing.T) {
	plaintext := RandomBytes(32)
	key := GenerateRSAKey()
	ciphertext, err := RSAEncrypt(plaintext, &key.PublicKey)
	assert.Nil(t, err)
	assert.NotNil(t, ciphertext)
}

func TestRSADecrypt(t *testing.T) {
	plaintext := RandomBytes(32)
	key := GenerateRSAKey()
	ciphertext, _ := RSAEncrypt(plaintext, &key.PublicKey)
	newPlaintext, err := RSADecrypt(ciphertext, key)
	assert.Nil(t, err)
	assert.Equal(t, plaintext, newPlaintext)
}

func TestRSASign(t *testing.T) {
	message := []byte("this is a message")
	key := GenerateRSAKey()
	sig, err := RSASign(message, key)
	assert.Nil(t, err)
	assert.NotNil(t, sig)
}

func TestRSAVerify(t *testing.T) {
	message := []byte("this is a message")
	key := GenerateRSAKey()
	sig, _ := RSASign(message, key)

	err := RSAVerify(message, sig, &key.PublicKey)
	assert.Nil(t, err)
}

func TestGroupRSAEncrypt(t *testing.T) {
    key1 := GenerateRSAKey()
    key2 := GenerateRSAKey()
    keys := make(map[string]string)
    keys["1"] = string(PemEncodeRSAPublic(&key1.PublicKey))
    keys["2"] = string(PemEncodeRSAPublic(&key2.PublicKey))

    plaintext := "this is a secret message"
    e, err := GroupRSAEncrypt(plaintext, keys)
    assert.Nil(t, err)
    assert.NotNil(t, e)
}

func TestGroupRSADecrypt(t *testing.T) {
    key1 := GenerateRSAKey()
    key2 := GenerateRSAKey()
    keys := make(map[string]string)
    keys["1"] = string(PemEncodeRSAPublic(&key1.PublicKey))
    keys["2"] = string(PemEncodeRSAPublic(&key2.PublicKey))

    plaintext := "this is a secret message"
    e, err := GroupRSAEncrypt(plaintext, keys)

    newPlaintext, err := GroupRSADecrypt(e, "1", string(PemEncodeRSAPrivate(key1)))
    assert.Nil(t, err)
    assert.Equal(t, plaintext, newPlaintext)
}

func TestSign(t *testing.T) {
	message := "this is a message"
	key := GenerateRSAKey()
	privateKey := string(PemEncodeRSAPrivate(key))
	sig := new(Signed)
	sig.Mode = SignatureModeSha256Rsa
	err := Sign(message, privateKey, sig)
	assert.Nil(t, err)
	assert.NotNil(t, sig.Signature)

	eckey := GenerateECKey()
	privateKey = string(PemEncodeECPrivate(eckey))
	sig = new(Signed)
	sig.Mode = SignatureModeSha256Ecdsa
	err = Sign(message, privateKey, sig)
	assert.Nil(t, err)
	assert.NotNil(t, sig.Signature)
}

func TestVerify(t *testing.T) {
	message := "this is a message"
	key := GenerateRSAKey()
	privateKey := string(PemEncodeRSAPrivate(key))
	sig := new(Signed)
	sig.Mode = SignatureModeSha256Rsa
	Sign(message, privateKey, sig)

	publicKey := string(PemEncodeRSAPublic(&key.PublicKey))
	err := Verify(sig, publicKey)
	assert.Nil(t, err)

	eckey := GenerateECKey()
	privateKey = string(PemEncodeECPrivate(eckey))
	sig = new(Signed)
	sig.Mode = SignatureModeSha256Ecdsa
	Sign(message, privateKey, sig)

	publicKey = string(PemEncodeECPublic(&eckey.PublicKey))
	err = Verify(sig, publicKey)
	assert.Nil(t, err)
}

func TestNewHMAC(t *testing.T) {
	mac := NewHMAC()
	assert.Equal(t, mac.Mode, HMACMode)
}

func TestHMACHelper(t *testing.T) {
	mac := NewHMAC()
	message := "message to be authenticated"
	key := RandomBytes(32)
	HMAC([]byte(message), key, mac)
	assert.Equal(t, mac.Message, message)
	assert.NotEqual(t, mac.Signature, "")
}

func TestHMACVerifyHelper(t *testing.T) {
	mac := NewHMAC()
	message := "message to be authenticated"
	key := RandomBytes(32)

	HMAC([]byte(message), key, mac)

	err := HMACVerify([]byte(message), key, mac)
	assert.Nil(t, err)
}

func TestExpandKeyHelper(t *testing.T) {
	key := RandomBytes(16)
	newKey, salt := ExpandKey(key)
	assert.Equal(t, len(salt), 16)
	assert.Equal(t, len(newKey), 32)
}
