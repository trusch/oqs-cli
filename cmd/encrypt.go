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
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/open-quantum-safe/liboqs-go/oqs"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/sha3"
)

// encryptCmd represents the encrypt command
var encryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "encrypt a message",
	Long:  `encrypt a message.`,
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

		server := oqs.KeyEncapsulation{}
		defer server.Clean() // clean up even in case of panic

		server.Init(algId, nil)
		keyCiphertext, sharedSecretServer := server.EncapSecret(keyBytes)
		hash := sha3.NewShake256()
		hash.Write(sharedSecretServer)
		aesKey := make([]byte, 32)
		hash.Read(aesKey[:])

		block, err := aes.NewCipher(aesKey)
		if err != nil {
			logrus.Fatal(err)
		}
		// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
		nonce := make([]byte, 12)
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			logrus.Fatal(err)
		}
		aesgcm, err := cipher.NewGCM(block)
		if err != nil {
			logrus.Fatal(err)
		}
		dataCiphertext := aesgcm.Seal(nil, nonce, dataBytes, nil)

		if output != "" {
			f, err := os.Create(output)
			if err != nil {
				logrus.Fatal(err)
			}
			defer f.Close()
			_, err = f.Write(keyCiphertext)
			if err != nil {
				logrus.Fatal(err)
			}
			_, err = f.Write(nonce)
			if err != nil {
				logrus.Fatal(err)
			}
			_, err = f.Write(dataCiphertext)
			if err != nil {
				logrus.Fatal(err)
			}
		} else {
			fmt.Printf("%x%x\n", keyCiphertext, dataCiphertext)
		}
	},
}

func init() {
	rootCmd.AddCommand(encryptCmd)
	encryptCmd.Flags().StringP("key", "k", "", "public key to use (may be a file)")
	encryptCmd.Flags().StringP("data", "d", "", "data")
	encryptCmd.Flags().StringP("algorithm", "a", "DEFAULT", "signature algorithm")
	encryptCmd.Flags().StringP("output", "o", "", "output file")
}
