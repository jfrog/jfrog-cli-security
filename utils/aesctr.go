package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"io"
	"os"

	"github.com/jfrog/jfrog-client-go/utils/errorutils"
)

// The encrypted file is a 16-byte IV followed by the AES-CTR ciphertext.
func decryptAesCtrFile(key []byte, encryptedFilePath, decryptedFilePath string) (err error) {
	encryptedFile, err := os.Open(encryptedFilePath)
	if err != nil {
		return errorutils.CheckError(err)
	}
	defer func() {
		err = errors.Join(err, errorutils.CheckError(encryptedFile.Close()))
	}()
	iv := make([]byte, aes.BlockSize)
	if _, err = io.ReadFull(encryptedFile, iv); err != nil {
		return errorutils.CheckErrorf("%s is too short to be an encrypted file", encryptedFilePath)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return errorutils.CheckError(err)
	}
	decryptedFile, err := os.OpenFile(decryptedFilePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return errorutils.CheckError(err)
	}
	defer func() {
		err = errors.Join(err, errorutils.CheckError(decryptedFile.Close()))
	}()
	_, err = io.Copy(decryptedFile, cipher.StreamReader{S: cipher.NewCTR(block, iv), R: encryptedFile})
	return errorutils.CheckError(err)
}
