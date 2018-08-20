package fraudproofs

import "errors"

// Transaction is a transaction of the blockchain.
type Transaction struct {
	keys [][]byte
	data [][]byte
}

// NewTransaction creates a new transaction with the given keys and data.
func NewTransaction(keys [][]byte, data [][]byte) (*Transaction, error) {
	t := &Transaction{keys, data}
	err := t.CheckTransaction()
	if err != nil {
		return nil, err
	}
	return t, nil
}

// CheckTransaction verifies whether a transaction is well-formed.
func (t *Transaction) CheckTransaction() (error) {
	if len(t.keys) != len(t.data) {
		return errors.New("number of keys does not match the number of data")
	}
	return nil
}


