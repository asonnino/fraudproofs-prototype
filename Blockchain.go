package fraudproofs_prototype

import (
	"bytes"
)

type Blockchain struct {
	length int
	last *Block
}

func NewBlockchain() *Blockchain {
	return &Blockchain{0,nil}
}

func (b *Blockchain) Append(block *Block) error {
	// rebuild block
	rebuiltBlock := NewBlock()
	for i := 0; i < len(block.transactions); i++ {
		rebuiltBlock.AddTransaction(block.transactions[i])
	}

	// verify state roots
	for i := 0; i < len(rebuiltBlock.interStateRoots); i++ {
		if len(block.interStateRoots)<=i || !bytes.Equal(rebuiltBlock.interStateRoots[i], block.interStateRoots[i]) {
			// TODO return fraud proof
			//t := rebuiltBlock.transactions[i*Step:(i+1)*Step]
			//ap := block.stateTree.AuditPath(D(t.data[0]), b.stateTree.N, b.stateTree.Base, key)
			//return &FraudProof{t, [][]byte{}, block.stateRoot}
			return nil
		}
	}

	// if all the checks pass, append to the blockchain
	if b.length == 0 {
		b.last = block
	} else {
		block.prev = b.last
		b.last = block
	}
	b.length++
	return nil
}
