package actions

import (
	"fmt"
	"github.com/goccy/go-yaml/parser"
	"github.com/goccy/go-yaml/printer"
	"github.com/spf13/cobra"
	"io/ioutil"
)

func Decrypt(cmd *cobra.Command, args []string) {
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

	var metadata eyamlMetadata
	metadata, err = ParseEyamlMetadata(astFile.Docs[0])
	if err != nil {
		fmt.Println("file is missing eyaml metadata")
		return
	}

	kp, err := getKeypair(metadata.PublicKey)
	if err != nil {
		fmt.Println(err)
		return
	}

	decrypter := kp.Decrypter()

	for _, nodeTree := range astFile.Docs {
		literals := YamlLiteralsFor(nodeTree.Body)
		for _, literalNode := range literals.List() {
			modify(literalNode, decrypter.Decrypt)
		}
	}

	yamlPrinter := printer.Printer{}
	for _, nodeTree := range astFile.Docs {
		rawDecryptedData := yamlPrinter.PrintNode(nodeTree)
		fmt.Print(string(rawDecryptedData))
	}
}