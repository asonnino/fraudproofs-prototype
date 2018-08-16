package fraudproofs_prototype

import "errors"


type Transaction struct {
	keys [][]byte
	data [][]byte
}

func NewTransaction(keys [][]byte, data [][]byte) (*Transaction, error) {
	if len(keys) != len(data) {
		return nil, errors.New("number of keys does not match the number of data")
	}
	return &Transaction{keys, data}, nil
}

func (t *Transaction) ToChunks(chunkSize int) [][]byte {
	// flat
	var buff []byte
	for i := 0; i < len(t.keys); i++ {
		buff = append(buff,t.keys[i]...)
		buff = append(buff,t.data[i]...)
	}
	// split to chunks
	var chunk []byte
	chunks := make([][]byte, 0, len(buff)/chunkSize+1)
	for len(buff) >= chunkSize {
		chunk, buff = buff[:chunkSize], buff[chunkSize:]
		chunks = append(chunks, chunk)
	}
	if len(buff) > 0 {
		chunks = append(chunks, buff[:])
	}
	return chunks
}

