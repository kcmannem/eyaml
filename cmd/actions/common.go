package actions

import (
	"fmt"
	"github.com/goccy/go-yaml/token"
	"os"
	"strings"
	"unicode"

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

type YamlNodeModifier interface {
	modify([]byte) ([]byte, error)
}

func grabWhiteSpace(origin string) string {
	nonWhitespaceSeeker := func(char rune) bool {
		return !unicode.IsSpace(char)
	}
	i := strings.IndexFunc(origin, nonWhitespaceSeeker)
	return strings.Repeat(" ", i)
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

func modifyAndReapplyWhitespaceForSequenceEntry(message string, modify actionFunc) (string, error) {
	splitLines := strings.Split(message, "\n")
	// drop an empty string that gets left behind no the split
	splitLines = splitLines[:len(splitLines)-1]

	for i, line := range splitLines {
		splitLines[i] = strings.TrimSpace(line)
	}
	scrubedMessage := strings.Join(splitLines, "\n")

	modifiedBytes, err := modify(
		[]byte(scrubedMessage),
	)
	if err != nil {
		return "", err
	}

	return string(modifiedBytes), nil
}

func modify(node ast.Node, modifier actionFunc) {
	switch stringyNode := node.(type) {
	case *ast.LiteralNode:
		modifyLiteral(stringyNode, modifier)
	case *ast.StringNode:
		modifyString(stringyNode, modifier)
	}

	// Both the Node.Value and Token.Origin/Value store the same string
	// value seperately. However, Token.Origin is used when node.String()
	// is called; which will be done during printing the nodes back to the
	// file after encryption

}

func modifyLiteral(node *ast.LiteralNode, modifier actionFunc) {
	stringNode := node.Value

	if secretbox.IsBoxedMessage([]byte(stringNode.Value)) {
		return
	}

	newNodeValue, err := modifyAndReapplyWhitespace(stringNode.Value, modifier)
	if err != nil {
		fmt.Println("Unable to modify node value: ", err)
		return
	}

	var newTokenOrigin string
	if node.GetToken().Prev.Type == token.SequenceEntryType {
		newTokenOrigin, err = modifyAndReapplyWhitespaceForSequenceEntry(stringNode.GetToken().Origin, modifier)
	} else {
		newTokenOrigin, err = modifyAndReapplyWhitespace(stringNode.GetToken().Origin, modifier)
	}
	if err != nil {
		fmt.Println("Unable to modify token origin: ", err)
		return
	}

	newTokenValue, err := modifyAndReapplyWhitespace(stringNode.GetToken().Value, modifier)
	if err != nil {
		fmt.Println("Unable to modify token value: ", err)
		return
	}

	stringNode.Value = newNodeValue
	stringNode.GetToken().Origin = newTokenOrigin
	stringNode.GetToken().Value = newTokenValue
}

func modifyString(node *ast.StringNode, modifier actionFunc) {
	if secretbox.IsBoxedMessage([]byte(node.Value)) {
		return
	}

	newNodeValue, err := modifyAndReapplyWhitespace(node.Value, modifier)
	if err != nil {
		fmt.Println("Unable to modify node value: ", err)
		return
	}

	newTokenOrigin, err := modifyAndReapplyWhitespace(node.GetToken().Origin, modifier)
	if err != nil {
		fmt.Println("Unable to modify token origin: ", err)
		return
	}

	newTokenValue, err := modifyAndReapplyWhitespace(node.GetToken().Value, modifier)
	if err != nil {
		fmt.Println("Unable to modify token value: ", err)
		return
	}

	node.Value = newNodeValue
	node.GetToken().Origin = newTokenOrigin
	node.GetToken().Value = newTokenValue
}
