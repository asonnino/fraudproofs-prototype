package fraudproofs

import (
	"github.com/NebulousLabs/merkletree"
	"github.com/musalbas/smt"
	"bytes"
	"errors"
	"crypto/sha256"
)

// Step defines the interval on which to compute intermediate state roots (must be a positive integer)
const Step int = 2
// ChunksSize defines the size of each chunk
const chunksSize int = 256

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
	for i := 0; i < len(t); i++ {
		err := t[i].CheckTransaction()
		if err != nil {
			return nil, err
		}
	}

	interStateRoots, stateRoot, err := fillStateTree(t, stateTree)
	if err != nil {
		return nil, err
	}

	dataTree := merkletree.New(sha256.New())
	dataRoot, err := fillDataTree(t, interStateRoots, dataTree)
	if err != nil {
		return nil, err
	}

    return &Block{
        dataRoot,
        stateRoot,
		t,
        nil,
		dataTree,
		interStateRoots}, nil
}

// fillStateTree fills the input state tree with key-values from the input transactions, and returns the state root and
// the intermediate state roots.
func fillStateTree(t []Transaction, stateTree *smt.SparseMerkleTree) ([][]byte, []byte, error){
	var stateRoot []byte
	var interStateRoots [][]byte

	for i := 0; i < len(t); i++ {
		for j := 0; j < len(t[i].writeKeys); j++ {
			root, err := stateTree.Update(t[i].writeKeys[j], t[i].newData[j])
			if err != nil {
				return nil, nil, err
			}
			stateRoot = make([]byte, len(root))
			copy(stateRoot, root)
		}

		if i != 0 && i % Step == 0 {
			interStateRoots = append(interStateRoots, stateRoot)
		}
	}
	if len(t)%Step == 0 {
		interStateRoots = append(interStateRoots, stateRoot)
	}

	return interStateRoots, stateRoot, nil
}

// fillDataTree fills the data tree and returns its root.
func fillDataTree(t []Transaction, interStateRoots [][]byte, dataTree *merkletree.Tree) ([]byte, error) {
	chunks, _, err := makeChunks(chunksSize, t, interStateRoots)
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(chunks); i++ {
		dataTree.Push(chunks[i])
	}
	return dataTree.Root(), nil
}

// makeChunks splits a set of transactions and state roots into multiple chunks.
func makeChunks(chunkSize int, t []Transaction, s [][]byte) ([][]byte, map[[256]byte]int, error) {
	if len(s) != int(len(t)/Step) {
		return nil, nil, errors.New("wrong number of intermediate state roots")
	}
	interStateRoots := make([][]byte, len(s))
	copy(interStateRoots, s)

	var buff []byte
	buffMap := make(map[[256]byte]int)
	for i := 0; i < len(t); i++ {
		for j := 0; j < len(t[i].writeKeys); j++ {
			buffMap[t[i].HashKey()] = len(buff)
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

	return chunks, buffMap, nil
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
			var data [][]byte
			for j := 0; j < len(t); j++ {
				for k := 0; k < len(t); k++ {
					keys = append(keys, t[j].writeKeys[k])
					data = append(data, t[j].newData[k])
				}
			}

			proofstate := make([][][]byte, len(keys))
			for j := 0; j < len(keys); j++ {
				proof, err := stateTree.ProveCompact(keys[j])
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
			chunksIndexes, _, err := b.getChunksIndexes(t)
			if err != nil {
				return nil, err
			}
			proofChunks := make([][][]byte, len(chunksIndexes))
			for j := 0; j < len(chunksIndexes); j++ {
				// merkletree.Tree cannot call SetIndex on Tree if Tree has not been reset
				// a dirty workaround is to copy the data tree
				tmpDataTree := merkletree.New(sha256.New())
				err = tmpDataTree.SetIndex(chunksIndexes[j])
				if err != nil {
					return nil, err
				}
				_, err := fillDataTree(b.transactions, b.interStateRoots, tmpDataTree)
				if err != nil {
					return nil, err
				}
				_, proof, _, _ := tmpDataTree.Prove()
				proofChunks[j] = proof
			}

			// 5. build the witnesses to allow reconstruction of the corrupted intermediate state
			// TODO: build the witnesses
			var witnesses [][][]byte

			return &FraudProof{
				keys,
				data,
				proofstate,
				prevStateRoot,
				b.interStateRoots[i],
				witnesses,
				proofChunks}, nil
		}
	}

	return nil, nil
}

// getChunksIndexes returns the indexes and number of chunks in which the given transactions are included
func (b *Block) getChunksIndexes(t []Transaction) ([]uint64, uint64, error) {
	chunks, buffMap, err := makeChunks(chunksSize, b.transactions, b.interStateRoots)
	if err != nil {
		return nil, 0, err
	}

	var chunksIndexes []uint64
	for i := 0; i < len(t); i++ {
		chunksIndexes = append(chunksIndexes, uint64(buffMap[t[i].HashKey()]/chunksSize))
	}

	uniquesMap := make(map[uint64]bool)
	var uniques []uint64
	for _, entry := range chunksIndexes {
		if _, value := uniquesMap[entry]; !value {
			uniquesMap[entry] = true
			uniques = append(uniques, entry)
		}
	}

	return uniques, uint64(len(chunks)), nil
}

// VerifyFraudProof verifies whether or not a fraud proof is valid.
func (b *Block) VerifyFraudProof(fp FraudProof) bool {
	// 1. check that the transactions, prevStateRoot, nextStateRoot are in the data tree
	chunksIndexes, numOfIndexes, _ := b.getChunksIndexes(b.transactions)
	for i := 0; i<len(fp.proofChunks); i++ {
		ret := merkletree.VerifyProof(sha256.New(), b.dataRoot, fp.proofChunks[i], chunksIndexes[i], numOfIndexes)
		if ret != true {
			return false
		}
	}

	// 2. check keys-values contained in the transaction are in the state tree
	for i := 0; i < len(fp.keys); i++ {
		ret := smt.VerifyCompactProof(fp.proofState[i], b.stateRoot, fp.keys[i], fp.data[i], sha256.New())
		if ret != true {
			return false
		}
	}

	// 3. verify that nextStateRoot is indeed built incorrectly using the witnesses
	// TODO

	return true
}


