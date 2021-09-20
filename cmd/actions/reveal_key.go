package actions

import (
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/goccy/go-yaml/parser"
	"github.com/spf13/cobra"
)

func RevealKey(cmd *cobra.Command, args []string) {
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

		decrypter := kp.Decrypter()
		literals := YamlLiteralsFor(nodeTree.Body)
		for _, literalNode := range literals.List() {
			// TODO: compare path
			//if literalNode.GetPath() ==
			rawDecryptedData, err := decrypter.Decrypt([]byte(strings.TrimSpace(literalNode.Value)))
			if err != nil {
				fmt.Println(err)
			}
			fmt.Println(string(rawDecryptedData))
		}
	}

	//yamlPrinter := printer.Printer{}
	//for _, nodeTree := range astFile.Docs {
	//	rawDecryptedData := yamlPrinter.PrintNode(nodeTree)
	//	fmt.Print(string(rawDecryptedData))
	//}
}