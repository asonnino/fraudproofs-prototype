package fraudproofs

import (
	"github.com/musalbas/smt"
	"crypto/sha512"
)

// Blockchain is a simple blockchain.
type Blockchain struct {
	// data structure
	length int
	last *Block

	// implementation specific
	stateTree *smt.SparseMerkleTree // sparse Merkle tree storing key-values of the transactions
}

// NewBlockchain creates an empty blockchain.
func NewBlockchain() *Blockchain {
	return &Blockchain{0,nil, smt.NewSparseMerkleTree(smt.NewSimpleMap(), sha512.New512_256())}
}

// Append appends a block to the blockchain or returns a fraud proof if the block is not constructed correctly.
func (bc *Blockchain) Append(b *Block) (*FraudProof, error) {
	fp, err := b.CheckBlock(bc.stateTree)
	if err != nil {
		return nil, err
	}
	if fp != nil {
		return fp, nil
	}

	if bc.length == 0 {
		bc.last = b
	} else {
		b.prev = bc.last
		bc.last = b
	}
	bc.length++
	return nil, nil
}
