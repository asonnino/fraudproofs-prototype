// Package fraudproofs implements fraud proofs.
package fraudproofs

// FraudProof is a fraud proof.
type FraudProof struct {
	// data structure
	writeKeys [][]byte
	oldData [][]byte
	newData [][]byte
	readKeys [][]byte
	readData [][]byte
	proofState [][][]byte
	chunks [][]byte
	proofChunks [][][]byte

	// implementation specific
	chunksIndexes []uint64
	numOfLeaves uint64
}
