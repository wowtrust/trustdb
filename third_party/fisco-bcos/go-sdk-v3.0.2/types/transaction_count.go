package types

type TransactionCount struct {
	BlockNumber int64 `json:"blockNumber"`
	FailedTxSum int64 `json:"failedTransactionCount"`
	TxSum       int64 `json:"transactionCount"`
}

// GetBlockNumber returns the transaction block height string
func (t *TransactionCount) GetBlockNumber() int64 {
	return t.BlockNumber
}

// GetFailedTxSum returns the transaction failed sum string
func (t *TransactionCount) GetFailedTxSum() int64 {
	return t.FailedTxSum
}

// GetTxSum returns the transaction sum string
func (t *TransactionCount) GetTxSum() int64 {
	return t.TxSum
}
