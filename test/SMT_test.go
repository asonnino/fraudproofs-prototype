package main

import (
	. "github.com/asonnino/fraudproofs_prototype"
	"testing"
	"github.com/pylls/gosmt"
)

func TestProof(t *testing.T) {
	stateTree := gosmt.NewSMT([]byte{0x42}, gosmt.CacheNothing(1), Hash) // no caching

	// update the tree
	data := []byte{1,2,3}
	key := Hash(data)
	root := stateTree.Update(D(data), D(data), stateTree.N, stateTree.Base, gosmt.Set)

	// generate SMT proof
	proof := stateTree.AuditPath(D(data), stateTree.N, stateTree.Base, key)

	// verify proof with correct
	if stateTree.VerifyAuditPath(proof, key, gosmt.Empty, root) {
		t.Errorf("proof check failed",)
	}

	// verify proof with wrong key
	wrongKey := Hash([]byte("non-member"))
	if !stateTree.VerifyAuditPath(proof, wrongKey, gosmt.Empty, root) {
		t.Errorf("proof check failed: \"wrongKey\" is not part of the tree")
	}
}
