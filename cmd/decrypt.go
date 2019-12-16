/*
Copyright © 2019 Tino Rusch <tino.rusch@gmail.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
package cmd

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"

	"github.com/open-quantum-safe/liboqs-go/oqs"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/sha3"
)

// decryptCmd represents the decrypt command
var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "decrypt a message",
	Long:  `Decrypt a message.`,
	Run: func(cmd *cobra.Command, args []string) {
		algId, _ := cmd.Flags().GetString("algorithm")
		output, _ := cmd.Flags().GetString("output")

		key, _ := cmd.Flags().GetString("key")
		keyBytes, err := ioutil.ReadFile(key)
		if err != nil {
			keyBytes, err = hex.DecodeString(key)
			if err != nil {
				logrus.Fatal(err)
			}
		}

		data, _ := cmd.Flags().GetString("data")
		dataBytes, err := ioutil.ReadFile(data)
		if err != nil {
			dataBytes = []byte(data)
		}
		dataInput := bytes.NewReader(dataBytes)

		client := oqs.KeyEncapsulation{}
		defer client.Clean() // clean up even in case of panic
		client.Init(algId, keyBytes)
		keyCiphertext := make([]byte, client.Details().LengthCiphertext)
		n, err := io.ReadFull(dataInput, keyCiphertext)
		if err != nil {
			logrus.Fatal(err)
		} else if n != client.Details().LengthCiphertext {
			logrus.Fatal("wrong key ciphertext lenght")
		}

		sharedSecretClient, err := client.DecapSecret(keyCiphertext)
		if err != nil {
			logrus.Fatal(err)
		}
		hash := sha3.NewShake256()
		hash.Write(sharedSecretClient)
		aesKey := make([]byte, 32)
		hash.Read(aesKey[:])

		nonce := make([]byte, 12)
		n, err = io.ReadFull(dataInput, nonce)
		if err != nil {
			logrus.Fatal(err)
		} else if n != 12 {
			logrus.Fatal("wrong nonce lenght")
		}

		block, err := aes.NewCipher(aesKey)
		if err != nil {
			panic(err.Error())
		}

		aesgcm, err := cipher.NewGCM(block)
		if err != nil {
			panic(err.Error())
		}

		dataCiphertext, err := ioutil.ReadAll(dataInput)
		if err != nil {
			logrus.Fatal(err)
		}
		plaintext, err := aesgcm.Open(nil, nonce, dataCiphertext, nil)
		if err != nil {
			logrus.Fatal(err)
		}

		if output != "" {
			err := ioutil.WriteFile(output, plaintext, 0644)
			if err != nil {
				logrus.Fatal(err)
			}
		} else {
			fmt.Println(string(plaintext))
		}

	},
}

func init() {
	rootCmd.AddCommand(decryptCmd)
	decryptCmd.Flags().StringP("key", "k", "", "private key to use (may be a file)")
	decryptCmd.Flags().StringP("data", "d", "", "data")
	decryptCmd.Flags().StringP("algorithm", "a", "DEFAULT", "signature algorithm")
	decryptCmd.Flags().StringP("output", "o", "", "output file")

}
