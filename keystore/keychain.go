package keystore

import (
	"fmt"
	"github.com/keybase/go-keychain"
)

type MacosKeychain struct {
}

func (k *MacosKeychain) Store(publicKey string, privateKey string) error {
	newEyamlKeypair := keychain.NewItem()
	newEyamlKeypair.SetSecClass(keychain.SecClassGenericPassword)
	newEyamlKeypair.SetService("eyaml")
	newEyamlKeypair.SetAccount("eyaml")
	newEyamlKeypair.SetLabel(fmt.Sprintf("eyaml-%s", publicKey))
	newEyamlKeypair.SetAccessGroup("eyaml.com.supersecretcorp")
	newEyamlKeypair.SetData([]byte(privateKey))
	newEyamlKeypair.SetSynchronizable(keychain.SynchronizableNo)
	newEyamlKeypair.SetAccessible(keychain.AccessibleWhenUnlocked)

	err := keychain.AddItem(newEyamlKeypair)

	if err != nil  {
		if err == keychain.ErrorDuplicateItem {
			return duplicateKeypairErr{publicKey: publicKey}
		}
		return err
	}
	return nil
}

func (k *MacosKeychain) FetchPrivateKey(publicKey string) (string, error) {
	query := keychain.NewItem()
	query.SetSecClass(keychain.SecClassGenericPassword)
	query.SetLabel(fmt.Sprintf("eyaml-%s", publicKey))
	query.SetService("eyaml")
	query.SetAccount("eyaml")
	query.SetAccessGroup("eyaml.com.supersecretcorp")
	query.SetMatchLimit(keychain.MatchLimitOne)
	query.SetReturnData(true)

	results, err := keychain.QueryItem(query)
	if err != nil {
		return "", err
	} else if len(results) != 1 {
		return  "", notFoundPrivateKeyErr{publicKey: publicKey}
	}

	privateKey := string(results[0].Data)

	return privateKey, nil
}
