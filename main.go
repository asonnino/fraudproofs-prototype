package fraudproofs_prototype

import "fmt"
//import "github.com/davecgh/go-spew/spew"


// TODO: 1. build tests
// TODO: 2. follow name conventions (eg. caps, get-set, ...)
// TODO: 3. build interface for the Merkle trees
// TODO: 4. use only one hash function

func main() {

	data := append([][]byte{},hash([]byte{10,10,10}))
	keys := append([][]byte{},data[0]) // same as the data? gosmt seems to generate keys on its own
	t1, err := NewTransaction(keys, data)
	t2, err := NewTransaction(keys, data)
	if err != nil {
		fmt.Println(err)
		return
	}

	b1 := NewBlock()
	b1.AddTransaction(*t1)
	b1.AddTransaction(*t2)

	// test
	b1.RootTransition(nil,*t1,nil)

	blockchain := NewBlockchain()
	blockchain.Append(b1)

	fmt.Println(t1.ToChunks(2))
	fmt.Println(t1)
	fmt.Println(b1)
	fmt.Println(blockchain)

}