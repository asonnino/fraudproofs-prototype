package fraudproofs

import (
	"testing"
	"crypto/sha256"
)


func TestTransaction(t *testing.T) {
	h := sha256.New()
	var writeKeys, newData, readKeys [][]byte

	newData = append(newData, []byte{0x01, 0x02, 0x03})
	newData = append(newData, []byte{0x01, 0x02, 0x03})

	h.Write(newData[0])
	writeKeys = append(writeKeys, h.Sum(nil))
	_, err :=  NewTransaction(writeKeys, newData, readKeys)
	if err == nil {
		t.Error("should return an error")
	}

	writeKeys = append(writeKeys, h.Sum(nil))
	_, err =  NewTransaction(writeKeys, newData, readKeys)
	if err != nil {
		t.Error(err)
	}
}

