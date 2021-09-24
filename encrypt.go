package eyaml

import (
	"fmt"
	"io/ioutil"

	"github.com/goccy/go-yaml/parser"
	"github.com/goccy/go-yaml/printer"
)


func Encrypt(filepath string) {
	if !fileExists(filepath) {
		fmt.Println("file doesn't exist")
		return
	}

	data, err := ioutil.ReadFile(filepath)
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

	kp, err := getIncompleteKeypair(metadata.PublicKey)
	if err != nil {
		fmt.Println(err)
		return
	}

	encrypter := kp.Encrypter(kp.Public)

	for _, nodeTree := range astFile.Docs[1:] {
		for _, literal:= range DfsSequence(nodeTree.Body).List() {
			modify(literal.node,  encrypter.Encrypt)
		}
	}

	yamlPrinter := printer.Printer{}
	for _, nodeTree := range astFile.Docs {
		rawEncryptedData := yamlPrinter.PrintNode(nodeTree)
		fmt.Print(string(rawEncryptedData))
	}
}
