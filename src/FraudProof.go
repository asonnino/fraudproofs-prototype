package main

type FraudProof struct {
	transactions  []Transaction
	witnesses [][]byte
	stateRoot []byte
}


func (e *FraudProof) Error() string {
	return "error"
}