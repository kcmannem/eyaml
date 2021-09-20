package actions

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"
	"github.com/kcmannem/eyaml/secretbox"
)

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

type actionFunc func([]byte) ([]byte, error)

func stubbedAction(stub []byte) ([]byte, error) {
	return stub, nil
}

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

func modifyAndReapplyWhitespace(message string, modify actionFunc) (string, error) {
	spaces := grabWhiteSpace(message)

	modifiedBytes, err := modify(
		[]byte(strings.TrimSpace(message)),
	)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s%s", spaces, string(modifiedBytes)), nil
}

func grabWhiteSpace(origin string) string {
	nonWhitespaceSeeker := func(char rune) bool {
		return !unicode.IsSpace(char)
	}
	i := strings.IndexFunc(origin, nonWhitespaceSeeker)
	return strings.Repeat(" ", i)
}

func modify(node *ast.StringNode, modifier actionFunc) {
	if secretbox.IsBoxedMessage([]byte(node.Value)) {
		return
	}

	// Both the Node.Value and Token.Origin/Value store the same string
	// value seperately. However, Token.Origin is used when node.String()
	// is called; which will be done during printing the nodes back to the
	// file after encryption

	newNodeValue, err := modifyAndReapplyWhitespace(node.Value, modifier)
	if err != nil {
		fmt.Println(err)
	}

	newTokenOrigin, err := modifyAndReapplyWhitespace(node.GetToken().Origin, modifier)
	if err != nil {
		fmt.Println(err)
	}

	newTokenValue, err := modifyAndReapplyWhitespace(node.GetToken().Value, modifier)
	if err != nil {
		fmt.Println(err)
	}

	node.Value = newNodeValue
	node.GetToken().Origin = newTokenOrigin
	node.GetToken().Value = newTokenValue
}


func walkOnSurface(node ast.Node) (eyamlMetadata, error) {
	metadata := eyamlMetadata{}

	switch nodeType := node.(type) {
	case *ast.MappingNode:
		for _, subnode := range nodeType.Values {
			if isPublicKeyNode(subnode) {
				metadata.PublicKey = subnode.Value.String()
			}
			//if isEncryptKeyNode(subnode) {
			//	metadata.EncryptFields = append(metadata.EncryptFields, subnode.Value.String())
			//}
		}
	}

	if metadata.PublicKey == "" {
		return metadata, fmt.Errorf("Could not find public key")
	}

	return metadata, nil
}

func ParseEyamlMetadata(doc *ast.DocumentNode) (eyamlMetadata, error) {
	var metadata eyamlMetadata
	if strings.Contains(doc.Body.GetComment().String(), "meta") {
		rawDocBytes, err := doc.Body.MarshalYAML()
		if err != nil {
			return metadata, err
		}
		yaml.Unmarshal(rawDocBytes, &metadata)
	} else {
		return metadata, fmt.Errorf("not a metadata document")
	}
	return metadata, nil
}

type eyamlMetadata struct {
	PublicKey     string   `yaml:"public_key, omitempty"`
	EncryptFields []string `yaml:"encrypt, omitempty"`
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
