package types

type TransactionDetail struct {
	Abi              string   `json:"abi"`
	BlockLimit       int64    `json:"blockLimit"`
	ChainID          string   `json:"chainID"`
	From             string   `json:"from"`
	GroupID          string   `json:"groupID"`
	Hash             string   `json:"hash"`
	ImportTime       int64    `json:"importTime"`
	Input            string   `json:"input"`
	Nonce            string   `json:"nonce"`
	Signature        string   `json:"signature"`
	To               string   `json:"to"`
	TransactionProof []string `json:"txProof"`
	Version          uint64   `json:"version"`
}

func (t *TransactionDetail) GetAbi() string {
	return t.Abi
}

func (t *TransactionDetail) GetBlockLimit() int64 {
	return t.BlockLimit
}

func (t *TransactionDetail) GetChainID() string {
	return t.ChainID
}

// GetValue returns the transaction pfrom address string
func (t *TransactionDetail) GetFrom() string {
	return t.From
}

func (t *TransactionDetail) GetGroupID() string {
	return t.GroupID
}

// GetValue returns the transaction hash string
func (t *TransactionDetail) GetHash() string {
	return t.Hash
}

func (t *TransactionDetail) GetImportTime() int64 {
	return t.ImportTime
}

// GetValue returns the transaction input string
func (t *TransactionDetail) GetInput() string {
	return t.Input
}

// GetValue returns the transaction once string
func (t *TransactionDetail) GetNonce() string {
	return t.Nonce
}

func (t *TransactionDetail) GetSignature() string {
	return t.Signature
}

// GetValue returns the transaction to address string
func (t *TransactionDetail) GetTo() string {
	return t.To
}

func (t *TransactionDetail) GetVersion() uint64 {
	return t.Version
}
