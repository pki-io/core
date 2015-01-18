package crypto

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGroupEncrypt(t *testing.T) {
    key1, _ := GenerateRSAKey()
    key2, _ := GenerateECKey()
    keys := make(map[string]string)
	k1, _ := PemEncodePublic(&key1.PublicKey)
	k2, _ := PemEncodePublic(&key2.PublicKey)
    keys["1"] = string(k1)
    keys["2"] = string(k2)

    plaintext := "this is a secret message"
    e, err := GroupEncrypt(plaintext, keys)
    assert.NoError(t, err)
    assert.NotNil(t, e)
}

func TestGroupDecrypt(t *testing.T) {
    key1, _ := GenerateRSAKey()
    key2, _ := GenerateECKey()
    keys := make(map[string]string)
	k1, _ := PemEncodePublic(&key1.PublicKey)
	k2, _ := PemEncodePublic(&key2.PublicKey)
	keys["1"] = string(k1)
	keys["2"] = string(k2)

    plaintext := "this is a secret message"
    e, _ := GroupEncrypt(plaintext, keys)
	pk1, _ := PemEncodePrivate(key1)
    newPlaintext, err := GroupDecrypt(e, "1", string(pk1))
    assert.NoError(t, err)
    assert.Equal(t, plaintext, newPlaintext)
}

func TestSign(t *testing.T) {
	message := "this is a message"
	rsakey, _ := GenerateRSAKey()
	eckey, _ := GenerateECKey()

	privateKey, _ := PemEncodePrivate(rsakey)
	sig := new(Signed)
	err := Sign(message, string(privateKey), sig)
	assert.NoError(t, err)
	assert.NotNil(t, sig.Signature)

	privateKey , _ = PemEncodePrivate(eckey)
	sig = new(Signed)
	err = Sign(message, string(privateKey), sig)
	assert.NoError(t, err)
	assert.NotNil(t, sig.Signature)
}

func TestVerify(t *testing.T) {
	message := "this is a message"
	rsakey, _ := GenerateRSAKey()
	eckey, _ := GenerateECKey()

	privateKey, _ := PemEncodePrivate(rsakey)
	sig := new(Signed)
	Sign(message, string(privateKey), sig)

	publicKey, _ := PemEncodePublic(&rsakey.PublicKey)
	err := Verify(sig, string(publicKey))
	assert.NoError(t, err)

	privateKey, _ = PemEncodePrivate(eckey)
	sig = new(Signed)
	Sign(message, string(privateKey), sig)

	publicKey, _ = PemEncodePublic(&eckey.PublicKey)
	err = Verify(sig, string(publicKey))
	assert.NoError(t, err)
}

func TestNewHMAC(t *testing.T) {
	mac := NewHMAC()
	message := "message to be authenticated"
	key, _ := RandomBytes(32)

	HMAC([]byte(message), key, mac)

	err := HMACVerify([]byte(message), key, mac)
	assert.Nil(t, err)
}
