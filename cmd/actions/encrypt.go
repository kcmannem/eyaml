package actions

import (
	"fmt"
	"io/ioutil"

	"github.com/goccy/go-yaml/parser"
	"github.com/goccy/go-yaml/printer"
	"github.com/spf13/cobra"
)


func Encrypt(cmd *cobra.Command, args []string) {
	if !fileExists(args[0]) {
		fmt.Println("file doesn't exist")
		return
	}

	data, err := ioutil.ReadFile(args[0])
	if err != nil {
		fmt.Println(err)
		return
	}

	astFile, err := parser.ParseBytes(data, 1)
	if err != nil {
		fmt.Println(err)
		return
	}

	for _, nodeTree := range astFile.Docs {
		metadata, err := walkOnSurface(nodeTree.Body)
		if err != nil {
			fmt.Println(err)
			return
		}

		kp, err := getKeypair(metadata.PublicKey)
		if err != nil {
			fmt.Println(err)
			return
		}

		encrypter := kp.Encrypter(kp.Public)

		walk(nodeTree.Body, encrypter.Encrypt)
	}

	yamlPrinter := printer.Printer{}
	for _, nodeTree := range astFile.Docs {
		rawEncryptedData := yamlPrinter.PrintNode(nodeTree)
		fmt.Print(string(rawEncryptedData))
	}
}
