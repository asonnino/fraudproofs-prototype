package fraudproofs

// Blockchain is a simple blockchain.
type Blockchain struct {
	length int
	last *Block
}

// NewBlockchain creates an empty blockchain.
func NewBlockchain() *Blockchain {
	return &Blockchain{0,nil}
}

// Append appends a block to the blockchain or returns a fraud proof if the block is not constructed correctly.
func (bc *Blockchain) Append(b *Block) (*FraudProof, error) {
	fp, err := b.CheckBlock()
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
