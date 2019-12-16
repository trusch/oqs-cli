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
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/open-quantum-safe/liboqs-go/oqs"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// verifyCmd represents the verify command
var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		algId, _ := cmd.Flags().GetString("algorithm")

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

		signature, _ := cmd.Flags().GetString("signature")
		signatureBytes, err := ioutil.ReadFile(signature)
		if err != nil {
			signatureBytes, err = hex.DecodeString(signature)
			if err != nil {
				logrus.Fatal(err)
			}
		}

		verifier := oqs.Signature{}
		defer verifier.Clean() // clean up even in case of panic
		verifier.Init(algId, nil)
		isValid, err := verifier.Verify(dataBytes, signatureBytes, keyBytes)
		if err != nil {
			logrus.Fatal(err)
		}
		if !isValid {
			fmt.Println("SIGNATURE NOT VALID")
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(verifyCmd)
	verifyCmd.Flags().StringP("key", "k", "", "public key to use (may be a file)")
	verifyCmd.Flags().StringP("data", "d", "", "data")
	verifyCmd.Flags().StringP("signature", "s", "", "signature")
	verifyCmd.Flags().StringP("algorithm", "a", "DEFAULT", "signature algorithm")
}
