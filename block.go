package fraudproofs

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"errors"

	"github.com/NebulousLabs/merkletree"
	"github.com/lazyledger/smt"
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
	prev            *Block           // link to the previous block
	dataTree        *merkletree.Tree // Merkle tree storing chunks
	interStateRoots [][]byte         // intermediate state roots (saved every 'step' transactions)
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

	dataTree := merkletree.New(sha512.New512_256())
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
func fillStateTree(t []Transaction, stateTree *smt.SparseMerkleTree) ([][]byte, []byte, error) {
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

		if i != 0 && i%Step == 0 {
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
		buffMap[t[i].HashKey()] = len(buff)
		buff = append(buff, t[i].Serialize()...)
		if i != 0 && i%Step == 0 {
			buff = append(buff, interStateRoots[0]...)
			interStateRoots = interStateRoots[1:]
		}
	}
	if len(t)%Step == 0 {
		buff = append(buff, interStateRoots[0]...)
	}

	var chunk []byte
	size := chunkSize - 1
	chunks := make([][]byte, 0, len(buff)/size+1)
	for len(buff) >= size {
		chunk, buff = buff[:size], buff[size:]
		chunk = append([]byte{0x0}, chunk...)
		chunks = append(chunks, chunk)
	}
	if len(buff) > 0 {
		chunk = buff[:]
		chunk = append([]byte{0x0}, chunk...)
		chunks = append(chunks, chunk)
	}

	for i := len(t) - 1; i >= 0; i-- {
		chunkIndex := buffMap[t[i].HashKey()] / chunksSize
		chunkPosition := byte(buffMap[t[i].HashKey()] % chunksSize)
		chunks[chunkIndex][0] = chunkPosition
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
			tx := rebuiltBlock.transactions[i*Step : (i+1)*Step]

			// 2. generate Merkle proofs of the keys-values contained in the transaction
			var writeKeys, oldData, readKeys, readData [][]byte
			for j := 0; j < len(tx); j++ {
				for k := 0; k < len(tx[j].writeKeys); k++ {
					writeKeys = append(writeKeys, tx[j].writeKeys[k])
					oldData = append(oldData, tx[j].oldData[k])
				}
				for k := 0; k < len(tx[j].readKeys); k++ {
					readKeys = append(readKeys, tx[j].readKeys[k])
					readData = append(readData, tx[j].readData[k])
				}
			}

			proofstate := make([]smt.SparseCompactMerkleProof, len(writeKeys))
			for j := 0; j < len(writeKeys); j++ {
				proof, err := stateTree.ProveCompact(writeKeys[j])
				if err != nil {
					return nil, err
				}
				proofstate[j] = proof
			}

			// 3. get chunks concerned by the proof
			// TODO compact 'makeChunks' and 'getChunksIndexes'
			chunksIndexes, _, err := b.getChunksIndexes(tx)
			if err != nil {
				return nil, err
			}
			chunks, _, err := makeChunks(chunksSize, b.transactions, b.interStateRoots)
			if err != nil {
				return nil, err
			}
			var concernedChunks [][]byte
			for j := 0; j < len(chunksIndexes); j++ {
				concernedChunks = append(concernedChunks, chunks[chunksIndexes[j]])
			}

			// 4. generate Merkle proofs of the transactions, previous state root, and next state root
			proofChunks := make([][][]byte, len(chunksIndexes))
			var numOfLeaves uint64
			for j := 0; j < len(chunksIndexes); j++ {
				// merkletree.Tree cannot call SetIndex on Tree if Tree has not been reset
				// a dirty workaround is to copy the data tree
				tmpDataTree := merkletree.New(sha512.New512_256())
				err = tmpDataTree.SetIndex(chunksIndexes[j])
				if err != nil {
					return nil, err
				}
				_, err := fillDataTree(b.transactions, b.interStateRoots, tmpDataTree)
				if err != nil {
					return nil, err
				}
				_, proof, _, leaves := tmpDataTree.Prove()
				numOfLeaves = leaves
				proofChunks[j] = proof
			}

			return &FraudProof{
				writeKeys,
				oldData,
				readKeys,
				readData,
				proofstate,
				concernedChunks,
				proofChunks,
				chunksIndexes,
				numOfLeaves}, nil
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
		index := uint64(buffMap[t[i].HashKey()] / chunksSize)
		length := int(binary.LittleEndian.Uint16(t[i].Serialize()[:MaxSize]))
		last := length / chunksSize
		for j := 0; j <= last; j++ {
			chunksIndexes = append(chunksIndexes, index+uint64(j))
		}
		if length > (chunksSize - buffMap[t[i].HashKey()]%chunksSize) {
			chunksIndexes = append(chunksIndexes, index+uint64(last)+1) // ugly fix
		}
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
	for i := 0; i < len(fp.proofChunks); i++ {
		ret := merkletree.VerifyProof(sha512.New512_256(), b.dataRoot, fp.proofChunks[i], fp.chunksIndexes[i], fp.numOfLeaves)
		if ret != true {
			return false
		}
	}

	// 2. extract new data from chunks
	var indexes []int
	var buff []byte
	for i := 0; i < len(fp.chunks); i++ {
		indexes = append(indexes, int(fp.chunks[i][0]))
		buff = append(buff, fp.chunks[i][1:]...)
	}

	var newData [][]byte
	buff = buff[indexes[0]:]
	for i := 0; len(buff) >= MaxSize; i++ {
		length := int(binary.LittleEndian.Uint16(buff[:MaxSize]))
		if len(buff) < length {
			break
		}
		t, _ := Deserialize(buff[:length])
		buff = buff[length:]
		newData = append(newData, t.newData...)
	}

	// 3. check keys-values contained in the transaction are in the state tree for old data
	subtree := smt.NewDeepSparseMerkleSubTree(smt.NewSimpleMap(), sha512.New512_256(), b.stateRoot)
	for i := 0; i < len(fp.writeKeys); i++ {
		proof, err := smt.DecompactProof(fp.proofState[i], sha512.New512_256())
		if err != nil {
			return false
		}
		err = subtree.AddBranch(proof, fp.writeKeys[i], newData[i])
		if err != nil {
			return false
		}
		// 4. update keys with new data
		_, err = subtree.Update(fp.writeKeys[i], newData[i])
		if err != nil {
			return false
		}
	}
	if !bytes.Equal(b.stateRoot, subtree.Root()) {
		return false
	}

	return true
}
