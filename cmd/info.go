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

	"github.com/open-quantum-safe/liboqs-go/oqs"
	"github.com/spf13/cobra"
)

// infoCmd represents the info command
var infoCmd = &cobra.Command{
	Use:   "info",
	Short: "info about available algorithms",
	Long:  `Info about available algorithms`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Supported signatures:")
		sigs := oqs.SupportedSigs()
		for _, sig := range sigs {
			fmt.Println(sig)
		}
		fmt.Println("\nSupported kems:")
		kems := oqs.SupportedKEMs()
		for _, kem := range kems {
			fmt.Println(kem)
		}
	},
}

func init() {
	rootCmd.AddCommand(infoCmd)
}
