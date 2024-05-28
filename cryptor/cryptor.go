package cryptor

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"github.com/gogf/gf/v2/errors/gcode"
	"github.com/gogf/gf/v2/errors/gerror"
	"github.com/gogf/gf/v2/util/grand"
)

type Cryptor struct {
	cipher    cipher.Block
	k         []byte
	encryptor cipher.BlockMode
	decryptor cipher.BlockMode
}

func NewCryptor(key []byte) *Cryptor {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}

	return &Cryptor{cipher: c, k: key}
}

func (receiver *Cryptor) Encrypt(plaintext []byte) string {
	ivValue := grand.B(16)
	plainText := PKCS7Padding(plaintext, receiver.cipher.BlockSize())
	encrypter := cipher.NewCBCEncrypter(receiver.cipher, ivValue)
	cipherText := make([]byte, len(plainText))
	encrypter.CryptBlocks(cipherText, plainText)
	return newPayload(cipherText, ivValue, receiver.k).String()
}
func (receiver *Cryptor) EncryptStr(plaintext string) string {
	return receiver.Encrypt([]byte(plaintext))
}

func (receiver *Cryptor) Decrypt(payload string) ([]byte, error) {
	p, err := parse(payload, receiver.k)
	if err != nil {
		return nil, err
	}

	blockSize := receiver.cipher.BlockSize()
	if len(p.Value) < blockSize {
		return nil, gerror.NewCode(gcode.CodeInvalidParameter, "cipherText too short")
	}

	if len(p.Value)%blockSize != 0 {
		return nil, gerror.NewCode(gcode.CodeInvalidParameter, "cipherText is not a multiple of the block size")
	}
	blockModel := cipher.NewCBCDecrypter(receiver.cipher, p.IV)
	plainText := make([]byte, len(p.Value))
	blockModel.CryptBlocks(plainText, p.Value)
	plainText, e := PKCS7UnPadding(plainText, blockSize)
	if e != nil {
		return nil, e
	}
	return plainText, nil
}
func PKCS7Padding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

// PKCS7UnPadding removes PKCS#7 padding from the source byte slice based on the given block size.
func PKCS7UnPadding(src []byte, blockSize int) ([]byte, error) {
	length := len(src)
	if blockSize <= 0 {
		return nil, errors.New(fmt.Sprintf("invalid blockSize: %d", blockSize))
	}

	if length%blockSize != 0 || length == 0 {
		return nil, errors.New("invalid data len")
	}

	unpadding := int(src[length-1])
	if unpadding > blockSize || unpadding == 0 {
		return nil, errors.New("invalid unpadding")
	}

	padding := src[length-unpadding:]
	for i := 0; i < unpadding; i++ {
		if padding[i] != byte(unpadding) {
			return nil, errors.New("invalid padding")
		}
	}

	return src[:(length - unpadding)], nil
}
