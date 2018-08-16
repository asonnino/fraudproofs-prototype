package main

import "github.com/NebulousLabs/merkletree"
import "crypto/sha256"
import "github.com/pylls/gosmt"
import "fmt"


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
        gosmt.NewSMT([]byte{TreeWideConstant}, gosmt.CacheNothing(1), hash), // naive caching strategy
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

func (b *Block) RootTransition(prevState []byte, t Transaction, w [][]byte) []byte {
	// TODO
	// test

	
	key := hash([]byte("non-member"))
	//key := t.data[0] // has to be 32 bytes
	ap := b.stateTree.AuditPath(D(t.data[0]), b.stateTree.N, b.stateTree.Base, key)
	fmt.Println(b.stateTree.VerifyAuditPath(ap, key, gosmt.Empty, b.stateRoot))
    return []byte{}
}

