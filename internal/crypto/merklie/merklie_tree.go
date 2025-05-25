package merkle

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
)

type Node struct {
	HashHex string
	Left    *Node
	Right   *Node
}

type MerkleTree struct {
	leaves []*Node
	root   *Node
}

func NewMerkleTree() *MerkleTree {
	return &MerkleTree{}
}

func hash(data string) string {
	digest := sha512.Sum512([]byte(data))
	return hex.EncodeToString(digest[:])
}

func (mt *MerkleTree) AddLeaf(data string) {
	leaf := &Node{HashHex: hash(data)}
	mt.leaves = append(mt.leaves, leaf)
	mt.root = mt.buildTree(mt.leaves)
}

func (mt *MerkleTree) RemoveLeaf(leafHash string) {
	index := -1
	for i, node := range mt.leaves {
		if node.HashHex == leafHash {
			index = i
			break
		}
	}
	if index != -1 {
		mt.leaves = append(mt.leaves[:index], mt.leaves[index+1:]...)
		mt.root = mt.buildTree(mt.leaves)
	}
}

func (mt *MerkleTree) GetRoot() string {
	if mt.root != nil {
		return mt.root.HashHex
	}
	return ""
}

func (mt *MerkleTree) buildTree(nodes []*Node) *Node {
	if len(nodes) == 0 {
		return nil
	}
	if len(nodes) == 1 {
		return nodes[0]
	}

	var nextLevel []*Node
	for i := 0; i < len(nodes); i += 2 {
		left := nodes[i]
		if i+1 < len(nodes) {
			right := nodes[i+1]
			combined := left.HashHex + right.HashHex
			parent := &Node{
				HashHex: hash(combined),
				Left:    left,
				Right:   right,
			}
			nextLevel = append(nextLevel, parent)
		} else {
			// Повторяем последний узел
			combined := left.HashHex + left.HashHex
			parent := &Node{
				HashHex: hash(combined),
				Left:    left,
				Right:   nil,
			}
			nextLevel = append(nextLevel, parent)
		}
	}
	return mt.buildTree(nextLevel)
}

func (mt *MerkleTree) GetProof(leafHash string) []struct {
	Hash    string
	IsRight bool
} {
	var proof []struct {
		Hash    string
		IsRight bool
	}

	var findPath func(*Node, *Node) ([]*Node, bool)
	findPath = func(current, target *Node) ([]*Node, bool) {
		if current == nil {
			return nil, false
		}
		if current == target {
			return []*Node{current}, true
		}
		if path, ok := findPath(current.Left, target); ok {
			return append(path, current), true
		}
		if path, ok := findPath(current.Right, target); ok {
			return append(path, current), true
		}
		return nil, false
	}

	var leaf *Node
	for _, node := range mt.leaves {
		if node.HashHex == leafHash {
			leaf = node
			break
		}
	}
	if leaf == nil {
		return proof
	}

	path, _ := findPath(mt.root, leaf)
	for i := 0; i < len(path)-1; i++ {
		parent := path[i+1]
		current := path[i]
		if parent.Left == current && parent.Right != nil {
			proof = append(proof, struct {
				Hash    string
				IsRight bool
			}{Hash: parent.Right.HashHex, IsRight: true})
		} else if parent.Right == current && parent.Left != nil {
			proof = append(proof, struct {
				Hash    string
				IsRight bool
			}{Hash: parent.Left.HashHex, IsRight: false})
		}
	}
	return proof
}

func (mt *MerkleTree) Serialize() string {
	var buffer bytes.Buffer
	var serializeNode func(*Node)

	serializeNode = func(node *Node) {
		if node == nil {
			buffer.WriteString("null")
			return
		}
		buffer.WriteString(fmt.Sprintf("{ \"hash\": \"%s\", ", node.HashHex))
		buffer.WriteString("\"left\": ")
		serializeNode(node.Left)
		buffer.WriteString(", \"right\": ")
		serializeNode(node.Right)
		buffer.WriteString(" }")
	}

	serializeNode(mt.root)
	return buffer.String()
}
