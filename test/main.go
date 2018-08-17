package main

import (
	"fmt"
	. "github.com/asonnino/fraudproofs_prototype"
)


// TODO: 1. build tests
// TODO: 2. follow name conventions (eg. caps, get-set, ...)
// TODO: 3. build interface for the Merkle trees
// TODO: 4. use only one hash function

func main() {

	data := append([][]byte{},Hash([]byte{10,10,10}))
	keys := append([][]byte{},data[0]) // same as the data? gosmt seems to generate keys on its own
	t1, err := NewTransaction(keys, data)
	//data = append([][]byte{},Hash([]byte{20,20,20}))
	//keys = append([][]byte{},data[0]) // same as the data? gosmt seems to generate keys on its own
	t2, err := NewTransaction(keys, data)
	if err != nil {
		fmt.Println(err)
		return
	}

	b1 := NewBlock()
	b1.AddTransaction(*t1)
	b1.AddTransaction(*t2)

	// test
	fmt.Println("Test SMT proof:",b1.TestSMT(*t1))

	blockchain := NewBlockchain()
	fp := blockchain.Append(b1.Corrupt())
	if fp != nil {
		fmt.Println("Test fraud proof:", b1.VerifyFraudProof(*fp))
	}

	fmt.Println("Chunks:", t1.ToChunks(2))
	fmt.Println("Transaction 1:", t1)
	fmt.Println("Block 1:", b1)
	fmt.Println("Blockchain:", blockchain)

}