package eyaml

import (
	"fmt"
	"github.com/fatih/color"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/kcmannem/eyaml/secretbox"
)

const keyStoreDir = ".eyaml/keys/"

func Keygen(write bool) {
	kp := secretbox.Keypair{}
	err := kp.Generate()
	if err != nil {
		fmt.Println(err)
	}

	publicKey := kp.PublicString()
	privateKey := kp.PrivateString()

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
}
