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

// kemCmd represents the kem command
var kemCmd = &cobra.Command{
	Use:   "kem",
	Short: "generate kem key pairs",
	Long:  `Generate kem key pairs.`,
	Run: func(cmd *cobra.Command, args []string) {
		algId, _ := cmd.Flags().GetString("algorithm")
		output, _ := cmd.Flags().GetString("output")
		client := oqs.KeyEncapsulation{}
		defer client.Clean() // clean up even in case of panic
		client.Init(algId, nil)
		pubKey, err := client.GenerateKeyPair()
		if err != nil {
			logrus.Fatal(err)
		}
		privKey := client.ExportSecretKey()
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
	keygenCmd.AddCommand(kemCmd)
	kemCmd.Flags().StringP("algorithm", "a", "DEFAULT", "signature algorithm")
	kemCmd.Flags().StringP("output", "o", "", "output file basename")

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// kemCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// kemCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
