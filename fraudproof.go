// Package fraudproofs implements fraud proofs.
package fraudproofs

import (
	"github.com/lazyledger/smt"
)

// FraudProof is a fraud proof.
type FraudProof struct {
	// data structure
	writeKeys [][]byte
	oldData [][]byte
	readKeys [][]byte
	readData [][]byte
	proofState []smt.SparseCompactMerkleProof
	chunks [][]byte
	proofChunks [][][]byte

	// implementation specific
	chunksIndexes []uint64
	numOfLeaves uint64
}
