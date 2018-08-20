package fraudproofs

import (
	"crypto/sha512"
)

// Hash implements an example of hash function.
func Hash(data ...[]byte) []byte {
	hasher := sha512.New512_256()
	for i := 0; i < len(data); i++ {
		hasher.Write(data[i])
	}
	return hasher.Sum(nil)
}

// ToChunks split a transaction and a state root into multiple chunks.
func ToChunks(chunkSize int, t Transaction, stateRoot []byte) [][]byte {
	var buff []byte
	for i := 0; i < len(t.keys); i++ {
		buff = append(buff,t.keys[i]...)
		buff = append(buff,t.data[i]...)
	}

	if stateRoot != nil {
		buff = append(buff,stateRoot...)
	}

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
