package crypto

import (
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
