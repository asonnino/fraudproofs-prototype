// Package fraudproofs implements fraud proofs.
package fraudproofs

// FraudProof is a fraud proof.
type FraudProof struct {
	keys [][]byte
	data [][]byte
	proofState [][][]byte
	prevStateRoot []byte
	nextStateRoot []byte
	witnesses [][][]byte
	proofChunks [][][]byte
}
