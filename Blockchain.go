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

func (b *Blockchain) Append(block *Block) *FraudProof {
	// rebuild block
	rebuiltBlock := NewBlock()
	for i := 0; i < len(block.transactions); i++ {
		rebuiltBlock.AddTransaction(block.transactions[i])
	}

	// verify state roots
	for i := 0; i < len(rebuiltBlock.interStateRoots); i++ {
		if len(block.interStateRoots)<=i || !bytes.Equal(rebuiltBlock.interStateRoots[i], block.interStateRoots[i]) {
			// compute transaction causing invalid intermediate state
			t := rebuiltBlock.transactions[i*Step:(i+1)*Step]

			// Merkle proofs of the keys-values contained in the transaction
			var ap [][][]byte
			var keys [][]byte
			for j := 0; j < len(t); j++ {
				keys = append(keys,t[j].keys[0]) // TODO update: transactions may contain multiple keys-values
				ap = append(
					ap,
					block.stateTree.AuditPath(D(t[j].data[0]), block.stateTree.N, block.stateTree.Base, t[j].keys[0]))
			}

			// if any, get the previous (ie. correct) state root
			var prevStateRoot []byte
			if i != 0 {
				prevStateRoot = block.interStateRoots[i-1]
			}

			return &FraudProof{
				keys,
				prevStateRoot,
				block.interStateRoots[i],
				[][]byte{}, // TODO
				[][]byte{}, // TODO
				[][]byte{}, // TODO
				ap}
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
