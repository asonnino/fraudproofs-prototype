package fraudproofs

import (
	"testing"
	"crypto/sha256"
	"github.com/musalbas/smt"
	"math/rand"
	"github.com/NebulousLabs/merkletree"
	"github.com/jinzhu/copier"
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

	goodTransaction, stateTree := generateBlockInput()
	goodBlock, err :=  NewBlock(goodTransaction, stateTree)
	if err != nil {
		test.Error(err)
	}

	_, err = goodBlock.CheckBlock(stateTree)
	if err != nil {
		test.Error(err)
	}

	badBlock := corruptBlockInterStates(goodBlock)
	goodFp, err := badBlock.CheckBlock(stateTree)
	if err != nil {
		test.Error(err)
	} else if goodFp == nil {
		test.Error("should return a fraud proof")
	}

	ret := badBlock.VerifyFraudProof(*goodFp)
	if ret != true {
		test.Error("fraud proof does not check")
	}

	corruptedFp := corruptFraudproofChunks(goodFp)
	ret = badBlock.VerifyFraudProof(*corruptedFp)
	if ret != false {
		test.Error("invalid fraud proof should not check")
	}

	corruptedFp = corruptFraudproofState(goodFp)
	ret = badBlock.VerifyFraudProof(*corruptedFp)
	if ret != false {
		test.Error("invalid fraud proof should not check")
	}

	badBlock = generateBlockWithCorruptedTransactions()
	_, err = badBlock.CheckBlock(stateTree)
	if err == nil {
		test.Error("should return an error")
	}

	// TODO: test witnesses
}

func TestBlockchain(test *testing.T) {
	blockchain := NewBlockchain()
	goodBlock, _ := NewBlock(generateBlockInput())
	blockchain.Append(goodBlock) // add a first block
	fp, err := blockchain.Append(goodBlock) // add a second block
	if err != nil {
		test.Error(err)
	} else if fp != nil {
		test.Error("should not return a fraud proof")
	}

	fp, err = blockchain.Append(corruptBlockInterStates(goodBlock))
	if err != nil {
		test.Error(err)
	} else if fp == nil {
		test.Error("should return a fraud proof")
	}

	_, err = blockchain.Append(generateBlockWithCorruptedTransactions())
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

	token = make([]byte, 3)
	rand.Read(token)
	readKeys = append(readKeys, token)

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

func generateBlockWithCorruptedTransactions() (*Block) {
	block, _ := NewBlock(generateBlockInput())
	t := block.transactions[0]
	block.transactions[0] = *corruptTransaction(&t)
	return block
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

func corruptFraudproofChunks(fp *FraudProof) (*FraudProof) {
	copyFp := &FraudProof{}
	copier.Copy(copyFp, fp)
	h := sha256.New()
	h.Write([]byte("random"))
	copyFp.proofChunks[0] = [][]byte{h.Sum(nil), h.Sum(nil)}
	return copyFp
}

func corruptFraudproofState(fp *FraudProof) (*FraudProof) {
	copyFp := &FraudProof{}
	copier.Copy(copyFp, fp)
	h := sha256.New()
	h.Write([]byte("random"))
	copyFp.proofState[0] = [][]byte{h.Sum(nil), h.Sum(nil)}
	return copyFp
}