package fraudproofs

import (
	"testing"
	"crypto/sha256"
	"github.com/musalbas/smt"
)


func TestTransaction(t *testing.T) {
	_, err :=  makeCorruptedTransaction()
	if err == nil {
		t.Error("should return an error")
	}

	_, err =  makeTransaction()
	if err != nil {
		t.Error(err)
	}
}


func TestBlock(t *testing.T) {
	_, err :=  makeCorruptedBlock()
	if err == nil {
		t.Error("should return an error")
	}

	_, err = makeBlock()
	if err != nil {
		t.Error(err)
	}
}

// ------------------

func makeTransaction() (*Transaction, error) {
	h := sha256.New()
	var writeKeys, newData, readKeys [][]byte

	newData = append(newData, []byte{0x01, 0x02, 0x03})
	newData = append(newData, []byte{0x01, 0x02, 0x03})

	h.Write(newData[0])
	writeKeys = append(writeKeys, h.Sum(nil))
	writeKeys = append(writeKeys, writeKeys[0])

	t, err :=  NewTransaction(writeKeys, newData, readKeys)
	return t, err
}

func makeCorruptedTransaction() (*Transaction, error) {
	h := sha256.New()
	var writeKeys, newData, readKeys [][]byte

	newData = append(newData, []byte{0x01, 0x02, 0x03})
	newData = append(newData, []byte{0x01, 0x02, 0x03})

	h.Write(newData[0])
	writeKeys = append(writeKeys, h.Sum(nil))

	t, err :=  NewTransaction(writeKeys, newData, readKeys)
	return t, err
}

func makeBlock() (*Block, error) {
	t1, _ := makeTransaction()
	t2, _ := makeTransaction()

	stateTree := smt.NewSparseMerkleTree(smt.NewSimpleMap(), sha256.New())
	b, err := NewBlock([]Transaction{*t1,*t2}, stateTree)
	return b, err
}

func makeCorruptedBlock() (*Block, error) {
	t1, _ := makeTransaction()
	t2, _ := makeTransaction()

	t1.writeKeys = t1.writeKeys[1:] // corrupt t1

	stateTree := smt.NewSparseMerkleTree(smt.NewSimpleMap(), sha256.New())
	b, err := NewBlock([]Transaction{*t1,*t2}, stateTree)
	return b, err
}