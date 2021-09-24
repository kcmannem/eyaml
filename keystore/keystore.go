package keystore

import "fmt"

type Keystore interface {
	Store(publicKey string, privateKey string) bool
	FetchPrivateKey(publicKey string) (string, error)
}

type notFoundPrivateKeyErr struct {
	publicKey string
}

func (e notFoundPrivateKeyErr) Error() string {
	return fmt.Sprintf("could not find private key for provided public key %s in keystore", e.publicKey)
}

type duplicateKeypairErr struct {
	publicKey string
}

func (e duplicateKeypairErr) Error() string {
	return fmt.Sprintf("duplicate public key %s already present in keystore", e.publicKey)
}
