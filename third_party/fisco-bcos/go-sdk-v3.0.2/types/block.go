package types

type Block struct {
	ConsensusWeights []uint64      `json:"consensusWeights"`
	ExtraData        string        `json:"extraData"`
	GasLimit         string        `json:"gasLimit"`
	GasUsed          string        `json:"gasUsed"`
	Hash             string        `json:"hash"`
	Number           uint64        `json:"number"`
	ParentInfo       []ParentInfo  `json:"parentInfo"`
	ReceiptsRoot     string        `json:"receiptsRoot"`
	Sealer           uint64        `json:"sealer"`
	SealerList       []string      `json:"sealerList"`
	SignatureList    []Signature   `json:"signatureList"`
	StateRoot        string        `json:"stateRoot"`
	Timestamp        uint64        `json:"timestamp"`
	Transactions     []interface{} `json:"transactions"`
	TxsRoot          string        `json:"txsRoot"`
	Version          uint64        `json:"version"`
}

type Signature struct {
	SealerIndex uint64 `json:"sealerIndex"`
	Signature   string `json:"signature"`
}

// GetIndex returns the signature index string
func (s *Signature) GetSealerIndex() uint64 {
	return s.SealerIndex
}

// GetSignature returns signature string
func (s *Signature) GetSignature() string {
	return s.Signature
}

type ParentInfo struct {
	BlockHash   string `json:"blockHash"`
	BlockNumber uint64 `json:"blockNumber"`
}

func (p *ParentInfo) GetBlockHash() string {
	return p.BlockHash
}

func (p *ParentInfo) GetBlockNumber() uint64 {
	return p.BlockNumber
}

func (B *Block) GetParentInfo() []ParentInfo {
	return B.ParentInfo
}

// GetGasLimit returns the block max gas limit string
func (B *Block) GetGasLimit() string {
	return B.GasLimit
}

// GetGasUsed returns the block gas used string
func (B *Block) GetGasUsed() string {
	return B.GasUsed
}

// GetHash returns the block hash string
func (B *Block) GetHash() string {
	return B.Hash
}

// GetNumber returns the block number uint64
func (B *Block) GetNumber() uint64 {
	return B.Number
}

// GetReceiptsRoot returns the block  receipts root string
func (B *Block) GetReceiptsRoot() string {
	return B.ReceiptsRoot
}

// GetSealer returns the sealer node sequence number string
func (B *Block) GetSealer() uint64 {
	return B.Sealer
}

// GetSealerList returns the sealer node list
func (B *Block) GetSealerList() []string {
	return B.SealerList
}

// GetSignatureList returns the block  signature list
func (B *Block) GetSignatureList() []Signature {
	return B.SignatureList
}

// GetTimestamp returns the block timestamp uint64
func (B *Block) GetTimestamp() uint64 {
	return B.Timestamp
}

// GetTransactions returns the blcok transcation list
func (B *Block) GetTransactions() []interface{} {
	return B.Transactions
}

func (B *Block) GetTxsRoot() string {
	return B.TxsRoot
}

func (B *Block) GetVersion() uint64 {
	return B.Version
}
