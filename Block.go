package fraudproofs_prototype

import "github.com/NebulousLabs/merkletree"
import "crypto/sha256"
import (
	"github.com/pylls/gosmt"
)

const Step int = 2
const ChunksSize int = 256
const TreeWideConstant byte = 0x42

type Block struct {
    // data structure
    dataRoot     []byte
    stateRoot    []byte
    transactions []Transaction

    // implementation specific
    prev            *Block // link to the previous block
    length          int // length of the block (ie. number of transactions in the block)
    dataTree        *merkletree.Tree // Merkle tree storing chunks
    stateTree       *gosmt.SMT // sparse Merkle tree storing key-values of the transactions
    interStateRoots [][]byte // intermediate state roots (saved every 'step' transactions)
}

func NewBlock() *Block {
    return &Block{
        []byte{},
        []byte{},
        []Transaction{},
        nil,
        0,
        merkletree.New(sha256.New()),
        gosmt.NewSMT([]byte{TreeWideConstant}, gosmt.CacheNothing(1), Hash), // no caching
        [][]byte{}}
}

func (b *Block) AddTransaction(t Transaction) {
    // add transaction
    b.transactions = append(b.transactions,t)
    b.length++
    
    // update state tree
	for i := 0; i < len(t.keys); i++ {
		b.stateRoot = b.stateTree.Update(D(t.data[i]), D(t.keys[i]), b.stateTree.N, b.stateTree.Base, gosmt.Set)
	}

	// update data tree
	chunks := t.ToChunks(ChunksSize)
	for i := 0; i < len(chunks); i++ {
		b.dataTree.Push(chunks[i])
	}

	// keep intermediate state roots
	if b.length%Step == 0 {
		b.interStateRoots = append(b.interStateRoots,b.stateRoot)
		b.dataTree.Push(b.stateRoot)
	}

	// update data root
	b.dataRoot = b.dataTree.Root()
}

func (b *Block) Corrupt() *Block {
	b.interStateRoots[0] = Hash([]byte("random"))
	return b
}

func (b *Block) TestSMT(t Transaction) bool {
	// non-inclusion should return True
	key := Hash([]byte("non-member")) // should return true
	//key := t.keys[0] // should return false (has to be 32 bytes)
	ap := b.stateTree.AuditPath(D(t.data[0]), b.stateTree.N, b.stateTree.Base, key)
	return b.stateTree.VerifyAuditPath(ap, key, gosmt.Empty, b.stateRoot)
}

func (b *Block) VerifyFraudProof(fp FraudProof) bool {
	// return true if the fraud proof is valid (ie. if a fraud happened)

	// check Merkle proofs of transactions, prevStateRoot, nextStateRoot
	// TODO

	// check Merkle proofs of the keys-values contained in the transaction
	for i := 0; i < len(fp.keys); i++ {
		// reminder: gosmt returns true if non-inclusion
		if b.stateTree.VerifyAuditPath(fp.witnesses[i], fp.keys[i], gosmt.Empty, b.stateRoot) {
			return false
		}
	}

	return true
}
