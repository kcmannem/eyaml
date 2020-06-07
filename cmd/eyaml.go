package cmd

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/fatih/color"
	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/parser"
	"github.com/goccy/go-yaml/printer"
	"github.com/kcmannem/eyaml/secretbox"
	"github.com/shopify/ejson"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "eyaml",
	Short: "Keep secrets safe in yaml files",
}

const keyStoreDir = ".eyaml/keys/"

var unencryptedFile string

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

type actionFunc func([]byte) ([]byte, error)

func isMetadataNode(node *ast.MappingValueNode) bool {
	return isPublicKeyNode(node) || isEncryptKeyNode(node)
}

const (
	publicKeyIndicator = "public_key"
	encryptIndicator   = "encrypt"
)

func isPublicKeyNode(node *ast.MappingValueNode) bool {
	if node.Key.String() == publicKeyIndicator {
		return true
	}
	return false
}
func isEncryptKeyNode(node *ast.MappingValueNode) bool {
	if node.Key.String() == encryptIndicator {
		return true
	}
	return false
}

func walk(node ast.Node, modify actionFunc) {
	switch nodeType := node.(type) {
	case *ast.MappingNode:
		for _, subnode := range nodeType.Values {
			if !isMetadataNode(subnode) {
				walk(subnode, modify)
			}
		}
	case *ast.MappingValueNode:
		if !isMetadataNode(nodeType) {
			digValues(nodeType.Value, modify)
		}
	case *ast.SequenceNode:
		for _, subnode := range nodeType.Values {
			digValues(subnode, modify)
		}
	}
	return
}

func digValues(node ast.Node, modify actionFunc) {
	switch nodeType := node.(type) {
	case *ast.MappingValueNode:
		digValues(nodeType.Value, modify)
	case *ast.MappingNode:
		for _, subnode := range nodeType.Values {
			digValues(subnode, modify)
		}
	case *ast.SequenceNode:
		for _, subnode := range nodeType.Values {
			digValues(subnode, modify)
		}
	case *ast.LiteralNode:
		// LiteralNode.Value points to a StringNode
		digValues(nodeType.Value, modify)
	case *ast.StringNode:
		modifiedBytes, err := modify([]byte(nodeType.Value))
		if err != nil {
			fmt.Println(err)
		}
		raw := string(modifiedBytes)
		// Both the Node.Value and Token.Origin/Value store the same string
		// value seperately. However, Token.Origin is used when node.String()
		// is called; which will be done during printing the nodes back to the
		// file after encryption
		nodeType.Value = raw
		nodeType.GetToken().Origin = raw
		nodeType.GetToken().Value = raw
	}
	return
}

func walkOnSurface(node ast.Node) (eyamlMetadata, error) {
	metadata := eyamlMetadata{}

	switch nodeType := node.(type) {
	case *ast.MappingNode:
		for _, subnode := range nodeType.Values {
			if isPublicKeyNode(subnode) {
				metadata.PublicKey = subnode.Value.String()
			}
			// if isEncryptKeyNode(subnode) {
			// 	metadata.EncryptFields = append(metadata.EncryptFields, subnode.Value.String())
			// }
		}
	}

	if metadata.PublicKey == "" {
		return metadata, fmt.Errorf("Could not find public key")
	}

	return metadata, nil
}

type eyamlMetadata struct {
	PublicKey     string   `yaml:"public_key,omitempty"`
	EncryptFields []string `yaml:"_encrypt,omitempty"`
}

var encryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "encrypt values in a yaml file",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
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

			var kp secretbox.Keypair
			err = kp.Generate()
			if err != nil {
				fmt.Println(err)
				return
			}

			var rawPubKey [32]byte
			copy(rawPubKey[:], metadata.PublicKey)
			encrypter := kp.Encrypter(rawPubKey)

			walk(nodeTree.Body, encrypter.Encrypt)
		}

		yamlPrinter := printer.Printer{}
		for _, nodeTree := range astFile.Docs {
			rawEncryptedData := yamlPrinter.PrintNode(nodeTree)
			fmt.Print(string(rawEncryptedData))
		}
	},
}

var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "Decrypt an eYaml file",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
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

			rawPubKey, err := hex.DecodeString(metadata.PublicKey)
			if err != nil {
				fmt.Println(err)
				return
			}
			var rawPubKey32 [32]byte
			copy(rawPubKey32[:], rawPubKey)

			privateKey, err := fetchPrivateKey(metadata.PublicKey)
			if err != nil {
				fmt.Println(err)
				return
			}

			var rawPrivKey32 [32]byte
			rawPrivKey, err := hex.DecodeString(privateKey)
			if err != nil {
				fmt.Println(err)
				return
			}
			copy(rawPrivKey32[:], rawPrivKey)

			kp := secretbox.Keypair{
				Public:  rawPubKey32,
				Private: rawPrivKey32,
			}

			// fmt.Println(hex.EncodeToString(rawPubKey32[:]), hex.EncodeToString(rawPrivKey32[:]))

			decrypter := kp.Decrypter()
			walk(nodeTree.Body, decrypter.Decrypt)

		}

		yamlPrinter := printer.Printer{}
		for _, nodeTree := range astFile.Docs {
			rawDecryptedData := yamlPrinter.PrintNode(nodeTree)
			fmt.Print(string(rawDecryptedData))
		}
	},
}

func fetchPrivateKey(publicKey string) (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	privateKeyFile := filepath.Join(homeDir, keyStoreDir, publicKey)
	privateKeyBytes, err := ioutil.ReadFile(privateKeyFile)
	if err != nil {
		return "", err
	}

	privateKeyBytes, err = hex.DecodeString(
		strings.TrimSpace(string(privateKeyBytes)),
	)
	if err != nil {
		return "", err
	}

	if len(privateKeyBytes) != 32 {
		return "", fmt.Errorf("invalid private key, expected 32 bytes")
	}

	return hex.EncodeToString(privateKeyBytes), nil
}

var write bool
var keygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate public-private keypair",
	Run: func(cmd *cobra.Command, args []string) {
		publicKey, privateKey, err := ejson.GenerateKeypair()
		if err != nil {
			fmt.Println(err)
		}

		cyan := color.New(color.FgCyan, color.Bold)
		green := color.New(color.FgGreen)

		if write {
			homeDir, err := os.UserHomeDir()
			if err != nil {
				fmt.Println(err)
			}

			keyFile := filepath.Join(homeDir, keyStoreDir, publicKey)
			err = ioutil.WriteFile(keyFile, append([]byte(privateKey), '\n'), 0440)
			if err != nil {
				fmt.Println(err)
			}

			green.Printf("Private key stored in %s\n", keyFile)
			cyan.Println("Public Key:")
			fmt.Println(publicKey)

			return
		}

		cyan.Println("Public Key:")
		fmt.Println(publicKey)
		cyan.Println("Private Key:")
		fmt.Println(privateKey)
	},
}

func init() {
	keygenCmd.Flags().BoolVarP(
		&write,
		"write",
		"w",
		false,
		"write to keystore dir",
	)
	rootCmd.AddCommand(keygenCmd)
	rootCmd.AddCommand(encryptCmd)
	rootCmd.AddCommand(decryptCmd)
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
