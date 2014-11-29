package crypto

import (
    "strings"
    "testing"
    "github.com/stretchr/testify/assert"
)

func TestRandomBytes(t *testing.T) {
    size := 10
    random, err := RandomBytes(size)
    assert.Nil(t, err, "shouldn't get an error")
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
    assert.Nil(t, err)
    assert.NotNil(t, key.D)
}

func TestPemEncodeRSAPrivate(t *testing.T) {
    key, _ := GenerateRSAKey()
    pemKey := PemEncodeRSAPrivate(key)
    assert.NotNil(t, pemKey)
    assert.Equal(t, strings.Contains(string(pemKey), "RSA PRIVATE KEY"), true)
}

func TestPemDecodeRSAPrivate(t *testing.T) {
    key, _ := GenerateRSAKey()
    pemKey := PemEncodeRSAPrivate(key)
    newKey, err := PemDecodeRSAPrivate(pemKey)
    assert.Nil(t, err)
    assert.Equal(t, key, newKey)
}

func TestPemEncodeRSAPublic(t *testing.T) {
    key, _ := GenerateRSAKey()
    pemKey := PemEncodeRSAPublic(&key.PublicKey)
    assert.NotNil(t, pemKey)
    assert.Equal(t, strings.Contains(string(pemKey), "RSA PUBLIC KEY"), true)
}

func TestPemDecodeRSAPublic(t *testing.T) {
    key, _ := GenerateRSAKey()
    pemKey := PemEncodeRSAPublic(&key.PublicKey)
    newKey, err := PemDecodeRSAPublic(pemKey)
    assert.Nil(t, err)
    assert.Equal(t, key.N, newKey.N)
}

func TestRSAEncrypt(t *testing.T) {
    plaintext, _ := RandomBytes(32)
    key, _ := GenerateRSAKey()
    ciphertext, err := RSAEncrypt(plaintext, &key.PublicKey)
    assert.Nil(t, err)
    assert.NotNil(t, ciphertext)
}

func TestRSADecrypt(t *testing.T) {
    plaintext, _ := RandomBytes(32)
    key, _ := GenerateRSAKey()
    ciphertext, _ := RSAEncrypt(plaintext, &key.PublicKey)
    newPlaintext, err := RSADecrypt(ciphertext, key)
    assert.Nil(t, err)
    assert.Equal(t, plaintext, newPlaintext)
}

func TestGroupEncrypt(t *testing.T) {
    key1, _ := GenerateRSAKey()
    key2, _ := GenerateRSAKey()
    keys := make(map[string]string)
    keys["1"] = string(PemEncodeRSAPublic(&key1.PublicKey))
    keys["2"] = string(PemEncodeRSAPublic(&key2.PublicKey))

    plaintext := "this is a secret message"
    e, err := GroupEncrypt(plaintext, keys)
    assert.Nil(t, err)
    assert.NotNil(t, e)
}

func TestGroupDecrypt(t *testing.T) {
    key1, _ := GenerateRSAKey()
    key2, _ := GenerateRSAKey()
    keys := make(map[string]string)
    keys["1"] = string(PemEncodeRSAPublic(&key1.PublicKey))
    keys["2"] = string(PemEncodeRSAPublic(&key2.PublicKey))

    plaintext := "this is a secret message"
    e, err := GroupEncrypt(plaintext, keys)

    newPlaintext, err := GroupDecrypt(e, "1", string(PemEncodeRSAPrivate(key1)))
    assert.Nil(t, err)
    assert.Equal(t, plaintext, newPlaintext)
}
