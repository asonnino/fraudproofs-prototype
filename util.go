package fraudproofs_prototype


import "crypto/sha512"
import "github.com/pylls/gosmt"
import "math/rand"
import "sort"



func hash(data ...[]byte) []byte {
	hasher := sha512.New512_256()
	for i := 0; i < len(data); i++ {
		hasher.Write(data[i])
	}
	return hasher.Sum(nil)
}


func getFreshData(size int) gosmt.D {
	var data gosmt.D
	for i := 0; i < size; i++ {
		key := make([]byte, 32)
		_, err := rand.Read(key)
		if err != nil {
			panic(err)
		}
		data = append(data, hash(key))
	}
	sort.Sort(gosmt.D(data))
	return data
}

func D(input []byte) gosmt.D {
	var data gosmt.D
	return append(data, input)
}
