package fraudproofs_prototype

type FraudProof struct {
	keys [][]byte
	prevStateRoot []byte
	nextStateRoot []byte
	proofTransaction [][]byte
	proofPrevStateRoot [][]byte
	proofNextStateRoot [][]byte
	witnesses [][][]byte

}

/*
func (e *FraudProof) Error() string {
	return "FraudProof"
}
*/