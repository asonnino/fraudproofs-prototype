package fraudproofs

import (
	"errors"
	"crypto/sha256"
	"encoding/binary"
)

// MaxSize is the number of bytes dedicated to store the size of the transaction's fields.
// TODO: this field cannot be changed because of the function 'binary.LittleEndian.PutUint16'
const MaxSize int = 2

// Transaction is a transaction of the blockchain.
// It is designed only for testing & benchmarking as it is implemented very naively.
type Transaction struct {
	writeKeys [][]byte
	newData [][]byte
	oldData [][]byte
	readKeys [][]byte
	readData [][]byte
	arbitrary []byte
}

// NewTransaction creates a new transaction with the given keys and data.
func NewTransaction(writeKeys, newData, oldData, readKeys, readData [][]byte, arbitrary []byte) (*Transaction, error) {
	//size := make([]byte, MaxSize)
	//binary.LittleEndian.PutUint16(size, uint16(len(writeKeys)+len(newData)+len(oldData)+len(readKeys)+len(readData)))
	t := &Transaction{
		writeKeys,newData,oldData,readKeys,readData,arbitrary}
	err := t.CheckTransaction()
	if err != nil {
		return nil, err
	}
	return t, nil
}

// CheckTransaction verifies whether a transaction is well-formed.
func (t *Transaction) CheckTransaction() (error) {
	if len(t.writeKeys) != len(t.newData) || len(t.writeKeys) != len(t.oldData) || len(t.readKeys) != len(t.readData) {
		return errors.New("number of keys does not match the number of data")
	}
	if len(t.writeKeys) != len(t.readKeys) || len(t.arbitrary) != 0{
		return errors.New("number of writeKeys should be equal to number of readKeys, and arbitrary data should" +
			"be empty; sorry for that (lazy implementation)")
	}

	return nil
}

// HashKey creates a compact representation of a transaction
func (t *Transaction) HashKey() [256]byte {
	var hashKey [256]byte
	h := sha256.New()
	h.Write(t.Serialize())
	copy(hashKey[:], h.Sum(nil)[:])
	return hashKey
}

// Serialize converts a transaction into an array of bytes.
// TODO: replace by a proper protocol buffer
func (t *Transaction) Serialize() []byte {
	var buff []byte
	numKeys := make([]byte, MaxSize)
	binary.LittleEndian.PutUint16(numKeys, uint16(len(t.writeKeys)))
	buff = append(buff, numKeys...)
	for i := 0; i < len(t.writeKeys); i++ {
		size := make([]byte, MaxSize)
		binary.LittleEndian.PutUint16(size, uint16(len(t.writeKeys[i])))
		buff = append(buff, size...)
		buff = append(buff, t.writeKeys[i]...)

		size = make([]byte, MaxSize)
		binary.LittleEndian.PutUint16(size, uint16(len(t.newData[i])))
		buff = append(buff, size...)
		buff = append(buff, t.newData[i]...)

		size = make([]byte, MaxSize)
		binary.LittleEndian.PutUint16(size, uint16(len(t.oldData[i])))
		buff = append(buff, size...)
		buff = append(buff, t.oldData[i]...)

		size = make([]byte, MaxSize)
		binary.LittleEndian.PutUint16(size, uint16(len(t.readKeys[i])))
		buff = append(buff, size...)
		buff = append(buff, t.readKeys[i]...)

		size = make([]byte, MaxSize)
		binary.LittleEndian.PutUint16(size, uint16(len(t.readData[i])))
		buff = append(buff, size...)
		buff = append(buff, t.readData[i]...)
	}
	return buff
}

// Deserialize converts a serialized transaction (ie. array of bytes) into a transaction structure.
// TODO: replace by a proper protocol buffer
func Deserialize(buff []byte) (*Transaction, error) {
	var writeKeys, newData, oldData, readKeys, readData [][]byte

	tmp, size := make([]byte, len(buff)), uint16(0)
	copy(tmp, buff)
	numKeys, tmp := binary.LittleEndian.Uint16(tmp[:MaxSize]), tmp[MaxSize:]
	for i := 0; i < int(numKeys); i++ {
		size, tmp = binary.LittleEndian.Uint16(tmp[:MaxSize]), tmp[MaxSize:]
		writeKeys, tmp = append(writeKeys, tmp[:size]), tmp[size:]

		size, tmp = binary.LittleEndian.Uint16(tmp[:MaxSize]), tmp[MaxSize:]
		newData, tmp = append(newData, tmp[:size]), tmp[size:]

		size, tmp = binary.LittleEndian.Uint16(tmp[:MaxSize]), tmp[MaxSize:]
		oldData, tmp = append(oldData, tmp[:size]), tmp[size:]

		size, tmp = binary.LittleEndian.Uint16(tmp[:MaxSize]), tmp[MaxSize:]
		readKeys, tmp = append(readKeys, tmp[:size]), tmp[size:]

		size, tmp = binary.LittleEndian.Uint16(tmp[:MaxSize]), tmp[MaxSize:]
		readData, tmp = append(readData, tmp[:size]), tmp[size:]
	}

	return NewTransaction(writeKeys, newData, oldData, readKeys, readData, []byte{})
}

