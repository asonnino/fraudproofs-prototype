package fraudproofs

import (
	"testing"
	"crypto/sha256"
	"github.com/musalbas/smt"
	"math/rand"
	"github.com/NebulousLabs/merkletree"
)


func TestTransaction(test *testing.T) {
	_, err :=  NewTransaction(generateCorruptedTransactionInput())
	if err == nil {
		test.Error("should return an error")
	}

	_, err =  NewTransaction(generateTransactionInput())
	if err != nil {
		test.Error(err)
	}
}


func TestBlock(test *testing.T) {
	_, err :=  NewBlock(generateCorruptedBlockInput())
	if err == nil {
		test.Error("should return an error")
	}

	t, stateTree := generateBlockInput()
	b, err :=  NewBlock(t, stateTree)
	if err != nil {
		test.Error(err)
	}

	_, err = b.CheckBlock(stateTree)
	if err != nil {
		test.Error(err)
	}

	b = corruptBlockInterStates(b)
	fp, err := b.CheckBlock(stateTree)
	if err != nil {
		test.Error(err)
	} else if fp == nil {
		test.Error("should return a fraud proof")
	}

	ret  := b.VerifyFraudProof(*fp)
	if ret != true {
		test.Error("fraud proof does not check")
	}


	b = corruptBlockTransactions(b)
	_, err = b.CheckBlock(stateTree)
	if err == nil {
		test.Error("should return an error")
	}
}


// ------------------


func generateTransactionInput() ([][]byte, [][]byte, [][]byte) {
	h := sha256.New()
	var writeKeys, newData, readKeys [][]byte

	token := make([]byte, 3)
	rand.Read(token)
	newData = append(newData, token)
	token = make([]byte, 3)
	rand.Read(token)
	newData = append(newData, token)

	h.Write(newData[0])
	writeKeys = append(writeKeys, h.Sum(nil))
	h.Reset()
	h.Write(newData[1])
	writeKeys = append(writeKeys, h.Sum(nil))

	return writeKeys, newData, readKeys
}

func generateCorruptedTransactionInput() ([][]byte, [][]byte, [][]byte) {
	writeKeys, newData, readKeys := generateTransactionInput()
	writeKeys = writeKeys[1:]
	return writeKeys, newData, readKeys
}

func corruptTransaction(t *Transaction) (*Transaction) {
	t.writeKeys = t.writeKeys[1:]
	return t
}

func generateBlockInput() ([]Transaction, *smt.SparseMerkleTree) {
	t1, _ := NewTransaction(generateTransactionInput())
	t2, _ := NewTransaction(generateTransactionInput())
	stateTree := smt.NewSparseMerkleTree(smt.NewSimpleMap(), sha256.New())
	return []Transaction{*t1,*t2}, stateTree
}

func generateCorruptedBlockInput() ([]Transaction, *smt.SparseMerkleTree) {
	t1, _ := NewTransaction(generateTransactionInput())
	t2, _ := NewTransaction(generateTransactionInput())

	t1 = corruptTransaction(t1)

	stateTree := smt.NewSparseMerkleTree(smt.NewSimpleMap(), sha256.New())
	return []Transaction{*t1,*t2}, stateTree
}

func corruptBlockTransactions(b *Block) (*Block) {
	t := b.transactions[0]
	b.transactions[0] = *corruptTransaction(&t)
	return b
}

func corruptBlockInterStates(b *Block) (*Block) {
	h := sha256.New()
	h.Write([]byte("random"))
	b.interStateRoots[0] = h.Sum(nil)

	dataTree := merkletree.New(sha256.New())
	dataRoot, _ := fillDataTree(b.transactions, b.interStateRoots, dataTree)

	return &Block{
		dataRoot,
		b.stateRoot,
		b.transactions,
		nil,
		dataTree,
		b.interStateRoots}
}