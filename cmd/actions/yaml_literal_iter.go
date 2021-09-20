package actions

import (
	"github.com/goccy/go-yaml/ast"
)

type addressedLiteral struct{
	path string
	node *ast.StringNode
}

type YamlLiterals struct {
	listByDFS []addressedLiteral
}

func YamlLiteralsFor(root ast.Node) *YamlLiterals {
	nodes := &YamlLiterals {
		listByDFS: make([]addressedLiteral, 0),
	}
	nodes.flatten(root)
	return nodes
}

func (i *YamlLiterals) List() []addressedLiteral {
	return i.listByDFS
}

func (i *YamlLiterals) flatten(node ast.Node) {
	switch nodeType := node.(type) {
	case *ast.MappingNode:
		for _, subnode := range nodeType.Values {
			if !isMetadataNode(subnode) {
				i.flatten(subnode)
			}
		}
	case *ast.MappingValueNode:
		if !isMetadataNode(nodeType) {
			i.flattenFurther(nodeType.Value)
		}
	case *ast.SequenceNode:
		for _, subnode := range nodeType.Values {
			i.flattenFurther(subnode)
		}
	}
	return
}

func (i *YamlLiterals) flattenFurther(node ast.Node) {
	switch nodeType := node.(type) {
	case *ast.MappingValueNode:
		i.flattenFurther(nodeType.Value)
	case *ast.MappingNode:
		for _, subnode := range nodeType.Values {
			i.flattenFurther(subnode)
		}
	case *ast.SequenceNode:
		for _, subnode := range nodeType.Values {
			i.flattenFurther(subnode)
		}
	case *ast.LiteralNode:
		// LiteralNode.Value points to a StringNode
		i.flattenFurther(nodeType.Value)
	case *ast.StringNode:
		i.listByDFS = append(i.listByDFS, addressedLiteral{
			path: nodeType.GetPath(),
			node: nodeType,
		})
	}
	return
}