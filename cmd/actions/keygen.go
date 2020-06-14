package actions

import (
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"io/ioutil"
	"os"
	"path/filepath"
	"fmt"

	"github.com/kcmannem/eyaml/secretbox"
)

const keyStoreDir = ".eyaml/keys/"
var Write bool

func Keygen(cmd *cobra.Command, args []string) {
	kp := secretbox.Keypair{}
	err := kp.Generate()
	if err != nil {
		fmt.Println(err)
	}

	publicKey := kp.PublicString()
	privateKey := kp.PrivateString()

	cyan := color.New(color.FgCyan, color.Bold)
	green := color.New(color.FgGreen)

	if Write {
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
}
