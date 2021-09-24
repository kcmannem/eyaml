package actions

import (
	"encoding/hex"
	"fmt"
	"github.com/kcmannem/eyaml/secretbox"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

func getIncompleteKeypair(publicKey string) (secretbox.Keypair, error){
	rawPubKey, err := hex.DecodeString(publicKey)
	if err != nil {
		return secretbox.Keypair{}, err
	}
	var rawPublicKey32 [32]byte
	copy(rawPublicKey32[:], rawPubKey)

	return secretbox.Keypair{
		Public:  rawPublicKey32,
	}, nil
}

func getKeypair(publicKey string) (secretbox.Keypair, error) {
	privateKeyBytes, err := fetchPrivateKey(publicKey)
	if err != nil {
		return secretbox.Keypair{}, err
	}
	var rawPrivateKey32 [32]byte
	copy(rawPrivateKey32[:], privateKeyBytes)

	rawPubKey, err := hex.DecodeString(publicKey)
	if err != nil {
		return secretbox.Keypair{}, err
	}
	var rawPublicKey32 [32]byte
	copy(rawPublicKey32[:], rawPubKey)

	return secretbox.Keypair{
		Public:  rawPublicKey32,
		Private: rawPrivateKey32,
	}, nil
}

func fetchPrivateKey(publicKey string) ([]byte, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return []byte{}, err
	}

	privateKeyFile := filepath.Join(homeDir, keyStoreDir, publicKey)
	privateKeyBytes, err := ioutil.ReadFile(privateKeyFile)
	if err != nil {
		return []byte{}, err
	}

	privateKeyBytes, err = hex.DecodeString(
		strings.TrimSpace(string(privateKeyBytes)),
	)
	if err != nil {
		return []byte{}, err
	}

	if len(privateKeyBytes) != 32 {
		return []byte{}, fmt.Errorf("invalid private key, expected 32 bytes")
	}

	return privateKeyBytes, nil
}

