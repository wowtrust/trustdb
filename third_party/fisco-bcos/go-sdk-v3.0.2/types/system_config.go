package types

type SystemConfig struct {
	BlockNumber int    `json:"blockNumber"`
	Value       string `json:"value"`
}

// GetBlockNumber returns the block number
func (s *SystemConfig) GetBlockNumber() int {
	return s.BlockNumber
}

// GetValue returns the value
func (s *SystemConfig) GetValue() string {
	return s.Value
}
