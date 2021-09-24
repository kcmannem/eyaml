package eyaml

import (
	"github.com/goccy/go-yaml/ast"
)

type addressedLiteral struct{
	path string
	node ast.Node
}

type YamlLiterals struct {
	listByDFS []addressedLiteral
}

func DfsSequence(root ast.Node) *YamlLiterals {
	nodes := &YamlLiterals{
		listByDFS: make([]addressedLiteral, 0),
	}
	nodes.DFS(root)
	return nodes
}

func (i *YamlLiterals) List() []addressedLiteral {
	return i.listByDFS
}

func (i *YamlLiterals) DFS(node ast.Node) {
	switch nodeType := node.(type) {
	case *ast.MappingNode:
		for _, subnode := range nodeType.Values {
			i.dfs(subnode)
		}
	case *ast.MappingValueNode:
		i.dfs(nodeType.Value)
	case *ast.SequenceNode:
		for _, subnode := range nodeType.Values {
			i.dfs(subnode)
		}
	}
	return
}

func (i *YamlLiterals) dfs(node ast.Node) {
	switch nodeType := node.(type) {
	case *ast.MappingValueNode:
		i.dfs(nodeType.Value)
	case *ast.MappingNode:
		for _, subnode := range nodeType.Values {
			i.dfs(subnode)
		}
	case *ast.SequenceNode:
		for _, subnode := range nodeType.Values {
			i.dfs(subnode)
		}
	case *ast.LiteralNode:
		// LiteralNode.Value points to a StringNode
		i.listByDFS = append(i.listByDFS, addressedLiteral{
			path: nodeType.GetPath(),
			node: nodeType,
		})
	case *ast.StringNode:
		i.listByDFS = append(i.listByDFS, addressedLiteral{
			path: nodeType.GetPath(),
			node: nodeType,
		})
	}
	return
}