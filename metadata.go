package eyaml

import (
	"fmt"
	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"
	"strings"
)

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
