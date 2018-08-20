// Package fraudproofs implements fraud proofs.
package fraudproofs

// FraudProof is a fraud proof.
type FraudProof struct {
	keys [][]byte
	prevStateRoot []byte
	nextStateRoot []byte
	proofState [][][]byte
	witnesses [][][]byte
	proofIndexChunks []uint64
	proofChunks [][][]byte
}
