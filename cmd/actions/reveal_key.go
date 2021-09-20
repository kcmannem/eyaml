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

	for _, nodeTree := range astFile.Docs[1:] {
		literals := YamlLiteralsFor(nodeTree.Body)

		for _, literal := range literals.List() {
			if strings.Contains(literal.path, args[1]) {
				rawDecryptedData, err := decrypter.Decrypt([]byte(strings.TrimSpace(literal.node.Value)))
				if err != nil {
					fmt.Println(err)
				}

				fmt.Println(string(rawDecryptedData))
				return
			}
		}
	}
	fmt.Println("could not find specified key")
}