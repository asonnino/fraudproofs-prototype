package fraudproofs

import (
	"crypto/sha256"
	"github.com/NebulousLabs/merkletree"
	"github.com/musalbas/smt"
	"bytes"
	"errors"
)

// Step defines the interval on which to compute intermediate state roots (must be a positive integer)
const Step int = 2
// ChunksSize defines the size of each chunk
const ChunksSize int = 256

// Block is a block of the blockchain
type Block struct {
    // data structure
    dataRoot     []byte
    stateRoot    []byte
    transactions []Transaction

    // implementation specific
    prev            *Block // link to the previous block
    dataTree        *merkletree.Tree // Merkle tree storing chunks
    interStateRoots [][]byte // intermediate state roots (saved every 'step' transactions)
}

// NewBlock creates a new block with the given transactions.
func NewBlock(t []Transaction, stateTree *smt.SparseMerkleTree) (*Block, error) {
	var dataRoot, stateRoot []byte
	dataTree := merkletree.New(sha256.New())
	transactions := make([]Transaction, len(t))
	interStateRoots := make([][]byte, int(len(t)/2))

	for i := 0; i < len(t); i++ {
		err := t[i].CheckTransaction()
		if err != nil {
			return nil, err
		}
		transactions = append(transactions,t[i])

		for j := 0; j < len(t[i].writeKeys); j++ {
			root, err := stateTree.Update(t[i].writeKeys[j], t[i].newData[j])
			if err != nil {
				return nil, err
			}
			copy(stateRoot, root)
		}

		if i != 0 && i % Step == 0 {
			interStateRoots = append(interStateRoots, stateRoot)
		}
	}
	if len(t)%Step == 0 {
		interStateRoots = append(interStateRoots, stateRoot)
	}

	chunks, err := makeChunks(ChunksSize, t, interStateRoots)
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(chunks); i++ {
		dataTree.Push(chunks[i])
	}
	copy(dataRoot, dataTree.Root())

    return &Block{
        dataRoot,
        stateRoot,
		transactions,
        nil,
		dataTree,
		interStateRoots}, nil
}

// makeChunks splits a set of transactions and state roots into multiple chunks.
func makeChunks(chunkSize int, t []Transaction, s [][]byte) ([][]byte, error) {
	if len(s) != int(len(t)/Step) {
		return nil, errors.New("wrong number of intermediate state roots")
	}
	interStateRoots := make([][]byte, len(s))
	copy(interStateRoots, s)

	var buff []byte
	for i := 0; i < len(t); i++ {
		for j := 0; j < len(t[i].writeKeys); j++ {
			buff = append(buff, t[i].writeKeys[j]...)
			buff = append(buff, t[i].newData[j]...)
		}

		if i != 0 && i%Step == 0 {
			buff = append(buff, interStateRoots[0]...)
			interStateRoots = interStateRoots[1:]
		}
	}
	if len(t)%Step == 0 {
		buff = append(buff, interStateRoots[0]...)
	}

	var chunk []byte
	chunks := make([][]byte, 0, len(buff)/chunkSize+1)
	for len(buff) >= chunkSize {
		chunk, buff = buff[:chunkSize], buff[chunkSize:]
		chunks = append(chunks, chunk)
	}
	if len(buff) > 0 {
		chunks = append(chunks, buff[:])
	}

	return chunks, nil
}


// CheckBlock checks that the block is constructed correctly, and returns a fraud proof if it is not.
func (b *Block) CheckBlock(stateTree *smt.SparseMerkleTree) (*FraudProof, error) {
	rebuiltBlock, err := NewBlock(b.transactions, stateTree)
	if err != nil {
		return nil, err
	}

	// verify that every intermediate state roots are constructed correctly
	for i := 0; i < len(rebuiltBlock.interStateRoots); i++ {
		if len(b.interStateRoots) <= i || !bytes.Equal(rebuiltBlock.interStateRoots[i], b.interStateRoots[i]) {
			// 1. get the transactions causing the (first) invalid intermediate state
			t := rebuiltBlock.transactions[i*Step:(i+1)*Step]

			// 2. generate Merkle proofs of the keys-values contained in the transaction
			var keys [][]byte
			for j := 0; j < len(t); j++ {
				for k := 0; k < len(t); k++ {
					keys = append(keys, t[j].writeKeys[k])
				}
			}

			proofstate := make([][][]byte, len(keys))
			for j := 0; j < len(keys); j++ {
				proof, err := stateTree.Prove(keys[j])
				if err != nil {
					return nil, err
				}
				proofstate[j] = proof
			}

			// 3. get the previous (ie. the correct) state root if any
			var prevStateRoot []byte
			if i != 0 {
				prevStateRoot = b.interStateRoots[i-1]
			} else {
				prevStateRoot = nil
			}

			// 4. generate Merkle proofs of the transactions, previous state root, and next state root
			chunksIndexes := b.getChunksIndexes(t)
			var proofIndexChunks []uint64
			proofChunks := make([][][]byte, len(chunksIndexes))
			for j := 0; j < len(chunksIndexes); j++ {
				b.dataTree.SetIndex(chunksIndexes[j])
				_, proof, proofIndex, _ := b.dataTree.Prove()
				proofIndexChunks = append(proofIndexChunks, proofIndex)
				copy(proofChunks[j], proof)
			}

			// 5. build the witnesses as described in the fraud proof paper
			// TODO: build the witnesses
			var witnesses [][][]byte

			return &FraudProof{
				keys,
				prevStateRoot,
				b.interStateRoots[i],
				proofstate,
				witnesses,
				proofIndexChunks,
				proofChunks}, nil
		}
	}

	return nil, nil
}

// getChunksIndexes returns the indexes of the chunks in which the given transactions are included
func (b *Block) getChunksIndexes(t []Transaction) []uint64 {
	// TODO: select the right chunks
	return []uint64{0}
}

// VerifyFraudProof verifies whether or not a fraud proof is valid.
func (b *Block) VerifyFraudProof(fp FraudProof) bool {
	// 1. check that the transactions, prevStateRoot, nextStateRoot are in the data tree
	// TODO

	// 2. check keys-values contained in the transaction are in the state tree
	for i := 0; i < len(fp.keys); i++ {
		// TODO
	}

	// 3. verify that nextStateRoot is indeed built incorrectly using the witnesses
	// TODO

	return true
}

/*
// Corrupt corrupts the block by modifying the specified intermediate state root.
func (b *Block) Corrupt(interStateRoot int) (*Block, error) {
	if interStateRoot >= len(b.interStateRoots) {
		return nil, errors.New("index out of bound")
	}
	b.interStateRoots[interStateRoot] = Hash([]byte("random"))
	return b, nil
}
*/

/*
// AddTransaction adds a transaction to the block.
func (b *Block) AddTransaction(t Transaction) error {
	err := t.CheckTransaction()
	if err != nil {
		return err
	}

    b.transactions = append(b.transactions,t)
    b.length++

	for i := 0; i < len(t.keys); i++ {
		root, err := b.stateTree.Update(t.keys[i], t.data[i])
		if err != nil {
			return err
		}
		b.stateRoot = root
	}

    var chunks [][]byte
	if b.length%Step == 0 {
		b.interStateRoots = append(b.interStateRoots,b.stateRoot)
		chunks = ToChunks(ChunksSize, t, b.stateRoot)
	} else {
		chunks = ToChunks(ChunksSize, t, nil)
	}

	for i := 0; i < len(chunks); i++ {
		b.dataTree.Push(chunks[i])
	}
	b.dataRoot = b.dataTree.Root()

	return nil
}
*/
