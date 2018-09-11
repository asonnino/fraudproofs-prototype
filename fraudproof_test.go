package fraudproofs

import (
	"bytes"
	//"crypto/sha256"
	"github.com/minio/sha256-simd"
	"fmt"
	"github.com/NebulousLabs/merkletree"
	"github.com/jinzhu/copier"
	"github.com/musalbas/smt"
	"math/rand"
	"testing"
	"time"
)


func TestTransaction(test *testing.T) {
	// create good transaction
	_, err :=  NewTransaction(generateCorruptedTransactionInput())
	if err == nil {
		test.Error("should return an error")
	}

	// create bad transaction
	goodT, err :=  NewTransaction(generateTransactionInput())
	if err != nil {
		test.Error(err)
	}

	// serialize and deserialize
	buff := goodT.Serialize()
	t, err := Deserialize(buff)
	if err != nil {
		test.Error(err)
	} else if bytes.Compare(t.Serialize(), buff) != 0 {
		test.Error("transaction not serialized and deserialize correctly")
	}
}


func TestBlock(test *testing.T) {
	// create bad block (corrupted transactions)
	_, err :=  NewBlock(generateCorruptedBlockInput())
	if err == nil {
		test.Error("should return an error")
	}

	// create good block
	goodTransaction, stateTree := generateBlockInput()
	goodBlock, err :=  NewBlock(goodTransaction, stateTree)
	if err != nil {
		test.Error(err)
	}

	// check good block
	_, err = goodBlock.CheckBlock(stateTree)
	if err != nil {
		test.Error(err)
	}

	// check a bad block (corrupted transactions)
	badBlock := generateBlockWithCorruptedTransactions()
	_, err = badBlock.CheckBlock(stateTree)
	if err == nil {
		test.Error("should return an error")
	}

	// check bad block (corrupted intermediate state)
	badBlock = corruptBlockInterStates(goodBlock)
	goodFp, err := badBlock.CheckBlock(stateTree)
	if err != nil {
		test.Error(err)
	} else if goodFp == nil {
		test.Error("should return a fraud proof")
	}

	// verify fraud proof of bad block
	ret := badBlock.VerifyFraudProof(*goodFp)
	if ret != true {
		test.Error("fraud proof does not check")
	}

	// verify corrupted fraud proof (corrupted chunks proof)
	corruptedFp := corruptFraudproofChunks(goodFp)
	ret = badBlock.VerifyFraudProof(*corruptedFp)
	if ret != false {
		test.Error("invalid fraud proof should not check")
	}

	// verify corrupted fraud proof (corrupted state proof)
	corruptedFp = corruptFraudproofState(goodFp)
	ret = badBlock.VerifyFraudProof(*corruptedFp)
	if ret != false {
		test.Error("invalid fraud proof should not check")
	}
}

func TestBlockchain(test *testing.T) {
	// add good blocks to blockchain
	blockchain := NewBlockchain()
	goodBlock, _ := NewBlock(generateBlockInput())
	blockchain.Append(goodBlock) // add a first block
	fp, err := blockchain.Append(goodBlock) // add a second block
	if err != nil {
		test.Error(err)
	} else if fp != nil {
		test.Error("should not return a fraud proof")
	}

	// add bad block to blockchain (corrupted intermediate state)
	fp, err = blockchain.Append(corruptBlockInterStates(goodBlock))
	if err != nil {
		test.Error(err)
	} else if fp == nil {
		test.Error("should return a fraud proof")
	}

	// add bad block to blockchain (corrupted transactions)
	_, err = blockchain.Append(generateBlockWithCorruptedTransactions())
	if err == nil {
		test.Error("should return an error")
	}
}

func TestTiming(test *testing.T) {
	// create good block
	goodTransaction, stateTree := generateBlockInput()
	goodBlock, err :=  NewBlock(goodTransaction, stateTree)
	if err != nil {
		test.Error(err)
	}

	// check bad block (corrupted intermediate state)
	goodBlock = corruptBlockInterStates(goodBlock)

	start := time.Now()
	goodFp, err := goodBlock.CheckBlock(stateTree)
	t := time.Now()
	elapsed := t.Sub(start)
	fmt.Println("generate proof: ", elapsed)

	if err != nil {
		test.Error(err)
	} else if goodFp == nil {
		test.Error("should return a fraud proof")
	}

	// verify fraud proof of bad block
	start = time.Now()
	ret := goodBlock.VerifyFraudProof(*goodFp)
	t = time.Now()
	elapsed = t.Sub(start)
	fmt.Println("verify proof: ", elapsed)

	if ret != true {
		test.Error("fraud proof does not check")
	}
}


// ------------------ helpers ------------------ //


func generateTransactionInput() ([][]byte, [][]byte, [][]byte, [][]byte, [][]byte, []byte) {
	var writeKeys, newData, oldData, readKeys, readData [][]byte

	// average Ethereum transaction size (225B)
	const numWriteKeys = 2
	const numReadKeys = numWriteKeys
	const sizeKeys = 1
	const sizeData = 33

	for i := 0; i < numWriteKeys; i++ {
		token := make([]byte, sizeKeys)
		//rand.Read(token)
		for j := 0; j < len(token); j++ {
			token[j] = 1
		}
		writeKeys = append(writeKeys, token)

		token = make([]byte, sizeData)
		//rand.Read(token)
		for j := 0; j < len(token); j++ {
			token[j] = 2
		}
		newData = append(newData, token)

		token = make([]byte, sizeData)
		//rand.Read(token)
		for j := 0; j < len(token); j++ {
			token[j] = 3
		}
		oldData = append(oldData, token)
	}
	for i := 0; i < numReadKeys; i++ {
		token := make([]byte, sizeKeys)
		rand.Read(token)
		//fmt.Println(len(token), token)
		//for j := 0; j < len(token); j++ {
		//	token[j] = byte(i)
		//}
		//fmt.Println(len(token), token)
		readKeys = append(readKeys, token)

		token = make([]byte, sizeData)
		//rand.Read(token)
		for j := 0; j < len(token); j++ {
			token[j] = 5
		}
		//fmt.Println(token)
		readData = append(readData, token)
	}

	return writeKeys, newData, oldData, readKeys, readData, []byte{}
}

func generateCorruptedTransactionInput() ([][]byte, [][]byte, [][]byte, [][]byte, [][]byte, []byte) {
	writeKeys, newData, oldData, readKeys, readData, arbitrary := generateTransactionInput()
	writeKeys = writeKeys[1:]
	return writeKeys, newData, oldData, readKeys, readData, arbitrary
}

func corruptTransaction(t *Transaction) (*Transaction) {
	t.writeKeys = t.writeKeys[1:]
	return t
}

func generateBlockInput() ([]Transaction, *smt.SparseMerkleTree) {
	// average Ethereum transactions per block (if block of 1MB)
	const numTransactions = 4444 // 4444
	t := make([]Transaction, numTransactions)
	for i := 0; i < len(t); i++ {
		tmp, _ := NewTransaction(generateTransactionInput())
		t[i] = *tmp
	}
	stateTree := smt.NewSparseMerkleTree(smt.NewSimpleMap(), sha256.New())
	return t, stateTree
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