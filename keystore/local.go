package keystore

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
)

const defaultStoreDir = ".eyaml/keys/"

type LocalStore struct {
	path string
}

func (k *LocalStore) Store(publicKey string, privateKey string) error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Println(err)
	}

	keyFile := filepath.Join(homeDir, defaultStoreDir, publicKey)
	err = ioutil.WriteFile(keyFile, append([]byte(privateKey), '\n'), 0440)
	if err != nil {
		return err
	}

	return nil
}

func (k *LocalStore) FetchPrivateKey(publicKey string) (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}

	privateKeyFile := filepath.Join(homeDir, defaultStoreDir, publicKey)
	privateKeyBytes, err := ioutil.ReadFile(privateKeyFile)
	if err != nil {
		return "", err
	}

	return string(privateKeyBytes), nil
}