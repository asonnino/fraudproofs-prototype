package fraudproofs

import (
	"testing"
	"crypto/sha256"
)


func TestTransaction(t *testing.T) {
	h := sha256.New()
	var data, keys [][]byte

	data = append(data, []byte{0x01, 0x02, 0x03})
	data = append(data, []byte{0x01, 0x02, 0x03})

	h.Write(data[0])
	keys = append(keys, h.Sum(nil))
	_, err :=  NewTransaction(keys, data)
	if err == nil {
		t.Error("should return an error")
	}

	keys = append(keys, h.Sum(nil))
	_, err =  NewTransaction(keys, data)
	if err != nil {
		t.Error(err)
	}
}