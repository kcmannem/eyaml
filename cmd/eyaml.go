package cmd

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/fatih/color"
	"github.com/shopify/ejson"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "eyaml",
	Short: "Keep secrets safe in yaml files",
}

const keyStoreDir = ".eyaml/keys/"

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
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
