package fraudproofs

import (
	"errors"
	"crypto/sha256"
)

// Transaction is a transaction of the blockchain.
type Transaction struct {
	writeKeys [][]byte
	newData [][]byte
	readKeys [][]byte
}

// NewTransaction creates a new transaction with the given keys and data.
func NewTransaction(writeKeys [][]byte, newData [][]byte, readKeys [][]byte) (*Transaction, error) {
	t := &Transaction{writeKeys, newData, readKeys}
	err := t.CheckTransaction()
	if err != nil {
		return nil, err
	}
	return t, nil
}

// CheckTransaction verifies whether a transaction is well-formed.
func (t *Transaction) CheckTransaction() (error) {
	if len(t.writeKeys) != len(t.newData) {
		return errors.New("number of keys does not match the number of data")
	}
	return nil
}

// HashKey creates a compact representation of a transaction
func (t *Transaction) HashKey() [256]byte {
	h := sha256.New()
	for i := 0; i < len(t.writeKeys); i++ {
		h.Write(t.writeKeys[i])
		h.Write(t.newData[i])
	}
	for i := 0; i < len(t.readKeys); i++ {
		h.Write(t.readKeys[i])
	}
	var hashKey [256]byte
	copy(hashKey[:], h.Sum(nil)[:])
	return hashKey
}

