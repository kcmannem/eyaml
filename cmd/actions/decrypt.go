package actions

import (
	"fmt"
	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/parser"
	"github.com/goccy/go-yaml/printer"
	"github.com/spf13/cobra"
	"io/ioutil"
	"strings"
)

var SearchPath string

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

	if SearchPath ==  "" {
		for _, nodeTree := range astFile.Docs[1:] {
			for _, literal:= range DfsSequence(nodeTree.Body).List() {
				modify(literal.node, decrypter.Decrypt)
			}
		}

		yamlPrinter := printer.Printer{}
		for _, nodeTree := range astFile.Docs[1:] {
			rawDecryptedData := yamlPrinter.PrintNode(nodeTree)
			fmt.Print(string(rawDecryptedData))
		}
	} else {
		for _, nodeTree := range astFile.Docs[1:] {
			for _, literal := range DfsSequence(nodeTree.Body).List() {
				if strings.Contains(literal.path, SearchPath) {
					stringValue := ""

					switch typedNode := literal.node.(type) {
					case *ast.LiteralNode:
						modifyLiteral(typedNode, decrypter.Decrypt)
						stringValue = typedNode.String()
					case *ast.StringNode:
						modifyString(typedNode, decrypter.Decrypt)
						stringValue = typedNode.String()
					}

					fmt.Println(stringValue)

					return
				}
			}
		}
	}
}