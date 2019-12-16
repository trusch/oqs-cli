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
	"fmt"
	"io/ioutil"

	"github.com/open-quantum-safe/liboqs-go/oqs"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// signatureCmd represents the signature command
var signatureCmd = &cobra.Command{
	Use:   "sig",
	Short: "generate key pairs for signing",
	Long:  `Generate key pairs for signing.`,
	Run: func(cmd *cobra.Command, args []string) {
		algId, _ := cmd.Flags().GetString("algorithm")
		output, _ := cmd.Flags().GetString("output")
		signer := oqs.Signature{}
		defer signer.Clean() // clean up even in case of panic
		signer.Init(algId, nil)
		pubKey, err := signer.GenerateKeyPair()
		if err != nil {
			logrus.Fatal(err)
		}
		privKey := signer.ExportSecretKey()
		if output == "" {
			fmt.Printf("pub: %x\n", pubKey)
			fmt.Printf("priv: %x\n", privKey)
		} else {
			if err := ioutil.WriteFile(output+".priv", privKey, 0400); err != nil {
				logrus.Fatal(err)
			}
			if err := ioutil.WriteFile(output+".pub", pubKey, 0644); err != nil {
				logrus.Fatal(err)
			}
		}
	},
}

func init() {
	keygenCmd.AddCommand(signatureCmd)
	signatureCmd.Flags().StringP("algorithm", "a", "DEFAULT", "signature algorithm")
	signatureCmd.Flags().StringP("output", "o", "", "output file basename")

}
