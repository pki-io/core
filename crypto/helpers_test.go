package crypto

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

func TestUUID(t *testing.T) {
	uuid := UUID()
	assert.Equal(t, 36, len(uuid), "incorrect size")
}

// TestUUIDNotEqual tests that two UUIDs aren't the same.
func TestUUIDNotEqual(t *testing.T) {
	uuid1 := UUID()
	uuid2 := UUID()
	assert.NotEqual(t, uuid1, uuid2, "can't be the same")
}

func TestRandomBytesSize(t *testing.T) {
	size := 10
	random, err := RandomBytes(size)
	assert.NoError(t, err)
	assert.Equal(t, size, len(random), "they should be equal")
}

// ThreatSpec TMv0.1 for TestRandomBytesNotEqual
// Tests RandomBytes for Use of Insufficiently Random Values (CWE-330)
// Note that this isn't a very good test

// TestRandomBytesNotEqual tests that two random byte arrays aren't the same.
// This should protect against basic problems like all 0s etc but is very basic.
func TestRandomBytesNotEqual(t *testing.T) {
	size := 10
	rand1, err := RandomBytes(size)
	assert.NoError(t, err)
	rand2, err := RandomBytes(size)
	assert.NoError(t, err)
	assert.NotEqual(t, rand1, rand2, "can't be the same")
}

func TestPad(t *testing.T) {
	size := 10
	msg := []byte("012345")
	padded := Pad(msg, size)
	assert.Equal(t, len(padded), size, "short input should be padded")

	msg = []byte("0123456789")
	padded = Pad(msg, size)
	expectedSize := size * 2
	assert.Equal(t, len(padded), expectedSize, "not a full block of padding")
}

func TestUnpad(t *testing.T) {
	size := 10
	expectedSize := 5
	padded := []byte{1, 2, 3, 4, 5, 5, 5, 5, 5, 5}
	assert.Equal(t, len(padded), size, "padding size is incorrect")
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
	assert.NotEqual(t, ciphertext, plaintext, "no encryption took place")
	assert.NotNil(t, iv)
}

// TestAESEncryptRepeat ensures that repeated AES encryption of a plaintext with the same key
// doesn't produce the same ciphertext. Ie. the IV used is different.
func TestAESEncryptRepeat(t *testing.T) {
	plaintext := []byte("secret message")
	key, _ := RandomBytes(32)
	ciphertext1, iv1, _ := AESEncrypt(plaintext, key)
	ciphertext2, iv2, _ := AESEncrypt(plaintext, key)
	assert.NotEqual(t, ciphertext1, ciphertext2, "should be different")
	assert.NotEqual(t, iv1, iv2, "should be different")
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

// TestGenerateRSAKeyRepeat tests that two generated RSA keys are different.
func TestGenerateRSAKeyRepeat(t *testing.T) {
	key1, _ := GenerateRSAKey()
	key2, _ := GenerateRSAKey()
	assert.NotEqual(t, key1.D, key2.D)
}

func TestGenerateECKey(t *testing.T) {
	key, err := GenerateECKey()
	assert.NoError(t, err)
	assert.NotNil(t, key.D)
}

// TestGenerateECKeyRepeat tests that two generated EC keys are different.
func TestGenerateECKeyRepeat(t *testing.T) {
	key1, _ := GenerateECKey()
	key2, _ := GenerateECKey()
	assert.NotEqual(t, key1.D, key2.D)
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
	assert.Equal(t, strings.Contains(string(pemKey), "EC PRIVATE KEY"), true)
}

// TestPemEncodePrivateRepeat tests that two different keys don't encode to the same thing
func TestPemEncodePrivateRepeat(t *testing.T) {
	rsakey1, _ := GenerateRSAKey()
	rsakey2, _ := GenerateRSAKey()
	eckey1, _ := GenerateECKey()
	eckey2, _ := GenerateECKey()

	pemKey1, _ := PemEncodePrivate(rsakey1)
	pemKey2, _ := PemEncodePrivate(rsakey2)
	assert.NotEqual(t, pemKey1, pemKey2)

	pemKey1, _ = PemEncodePrivate(eckey1)
	pemKey2, _ = PemEncodePrivate(eckey2)
	assert.NotEqual(t, pemKey1, pemKey2)
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
	assert.Equal(t, strings.Contains(string(pemKey), "EC PUBLIC KEY"), true)
}

func TestPemEncodePublicRepeat(t *testing.T) {
	rsakey1, _ := GenerateRSAKey()
	rsakey2, _ := GenerateRSAKey()
	eckey1, _ := GenerateECKey()
	eckey2, _ := GenerateECKey()

	pemKey1, _ := PemEncodePublic(&rsakey1.PublicKey)
	pemKey2, _ := PemEncodePublic(&rsakey2.PublicKey)
	assert.NotEqual(t, pemKey1, pemKey2)

	pemKey1, _ = PemEncodePublic(&eckey1.PublicKey)
	pemKey2, _ = PemEncodePublic(&eckey2.PublicKey)
	assert.NotEqual(t, pemKey1, pemKey2)
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

func TestEncryptRepeat(t *testing.T) {
	plaintext, _ := RandomBytes(32)

	rsakey1, _ := GenerateRSAKey()
	rsakey2, _ := GenerateRSAKey()
	eckey1, _ := GenerateECKey()
	eckey2, _ := GenerateECKey()

	ciphertext1, _ := Encrypt(plaintext, &rsakey1.PublicKey)
	ciphertext2, _ := Encrypt(plaintext, &rsakey2.PublicKey)
	assert.NotEqual(t, ciphertext1, ciphertext2)

	ciphertext1, _ = Encrypt(plaintext, &eckey1.PublicKey)
	ciphertext2, _ = Encrypt(plaintext, &eckey2.PublicKey)
	assert.NotEqual(t, ciphertext1, ciphertext2)
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

// TestSignMessageRepeat tests that repeated signatures with the same private key produces different signatures
func TestSignMessageRepeat(t *testing.T) {
	message := []byte("this is a message")
	rsakey1, _ := GenerateRSAKey()
	rsakey2, _ := GenerateRSAKey()
	eckey1, _ := GenerateECKey()
	eckey2, _ := GenerateECKey()

	sig1, _ := SignMessage(message, rsakey1)
	sig2, _ := SignMessage(message, rsakey2)
	assert.NotEqual(t, sig1, sig2)

	sig1, _ = SignMessage(message, eckey1)
	sig2, _ = SignMessage(message, eckey2)
	assert.NotEqual(t, sig1, sig2)
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

func TestHMAC(t *testing.T) {
	mac := NewSignature(SignatureModeSha256Hmac)
	message := "message to be authenticated"
	key, _ := RandomBytes(32)
	HMAC([]byte(message), key, mac)
	assert.Equal(t, mac.Message, message)
	assert.NotEqual(t, mac.Signature, "")
}

// TestHMACRepeat tests that a message HMAC'd with a single key always produces the same result
func TestHMACRepeat(t *testing.T) {
	mac1 := NewSignature(SignatureModeSha256Hmac)
	mac2 := NewSignature(SignatureModeSha256Hmac)
	message := "message to be authenticated"
	key, _ := RandomBytes(32)

	HMAC([]byte(message), key, mac1)
	HMAC([]byte(message), key, mac2)

	assert.Equal(t, mac1.Signature, mac2.Signature)
}

func TestHMACVerify(t *testing.T) {
	mac := NewSignature(SignatureModeSha256Hmac)
	message := "message to be authenticated"
	key, _ := RandomBytes(32)

	HMAC([]byte(message), key, mac)

	signature, _ := Base64Decode([]byte(mac.Signature))
	err := HMACVerify([]byte(message), key, signature)
	assert.Nil(t, err)
}

func TestExpandKey(t *testing.T) {
	key, _ := RandomBytes(16)
	newKey, salt, err := ExpandKey(key, nil)
	assert.NoError(t, err)
	assert.Equal(t, len(salt), 16)
	assert.Equal(t, len(newKey), 32)
}

// TestExpandKeyRepeat tests that repeated key expansion for a single key produces different results
func TestExpandKeyRepeat(t *testing.T) {
	key, _ := RandomBytes(16)
	newKey1, salt1, _ := ExpandKey(key, nil)
	newKey2, salt2, _ := ExpandKey(key, nil)
	assert.NotEqual(t, newKey1, newKey2)
	assert.NotEqual(t, salt1, salt2)
}

func TestExpandKeyWithSalt(t *testing.T) {
	key, _ := RandomBytes(16)
	salt, _ := RandomBytes(16)
	newKey, newSalt, err := ExpandKey(key, salt)
	assert.NoError(t, err)
	assert.Equal(t, salt, newSalt)
	assert.Equal(t, len(newKey), 32)
}

// TestExpandKeyWithSaltRepeat tests that repeated key expansion for a given key and salt gives the same result
func TestExpandKeyWithSaltRepeat(t *testing.T) {
	key, _ := RandomBytes(16)
	salt, _ := RandomBytes(16)

	newKey1, newSalt1, _ := ExpandKey(key, salt)
	newKey2, newSalt2, _ := ExpandKey(key, salt)
	assert.Equal(t, newKey1, newKey2)
	assert.Equal(t, newSalt1, newSalt2)
}
