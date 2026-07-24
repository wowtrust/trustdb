package types

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
)

// Receipt represents the results of a transaction.
type Receipt struct {
	BlockNumber     int       `json:"blockNumber"`
	ContractAddress string    `json:"contractAddress"`
	From            string    `json:"from"`
	GasUsed         string    `json:"gasUsed"`
	Hash            string    `json:"hash"`
	Input           string    `json:"input"`
	Logs            []*NewLog `json:"logEntries"`
	Message         string    `json:"message"`
	Output          string    `json:"output"`
	Status          int       `json:"status"`
	To              string    `json:"to"`
	TransactionHash string    `json:"transactionHash"`
	ReceiptProof    []string  `json:"txReceiptProof"`
	Version         uint64    `json:"version"`
}

const (
	Success                    = iota
	Unknown                    = 1
	OutOfGasLimit              = 2 ///< Too little gas to pay for the base transaction cost.
	NotEnoughCash              = 7
	BadInstruction             = 10
	BadJumpDestination         = 11
	OutOfGas                   = 12 ///< Ran out of gas executing code of the transaction.
	OutOfStack                 = 13 ///< Ran out of stack executing code of the transaction.
	StackUnderflow             = 14
	PrecompiledError           = 15
	RevertInstruction          = 16
	ContractAddressAlreadyUsed = 17
	PermissionDenied           = 18
	CallAddressError           = 19
	GasOverflow                = 20
	ContractFrozen             = 21
	AccountFrozen              = 22
	AccountAbolished           = 23
	ContractAbolished          = 24
	WASMValidationFailure      = 32
	WASMArgumentOutOfRange     = 33
	WASMUnreachableInstruction = 34
	WASMTrap                   = 35
	NonceCheckFail             = 10000 /// txPool related errors
	BlockLimitCheckFail        = 10001
	TxPoolIsFull               = 10002
	Malformed                  = 10003
	AlreadyInTxPool            = 10004
	TxAlreadyInChain           = 10005
	InvalidChainId             = 10006
	InvalidGroupId             = 10007
	InvalidSignature           = 10008
	RequestNotBelongToTheGroup = 10009
	TransactionPoolTimeout     = 10010
	AlreadyInTxPoolAndAccept   = 10011
)

// GetStatusMessage returns the status message
func getStatusMessage(status int) string {
	var message string
	switch status {
	case Success:
		message = "success"
	case Unknown:
		message = "unknown"
	case NotEnoughCash:
		message = "not enough cash"
	case BadInstruction:
		message = "bad instruction"
	case BadJumpDestination:
		message = "bad jump destination"
	case OutOfGas:
		message = "out of gas"
	case OutOfStack:
		message = "out of stack"
	case StackUnderflow:
		message = "stack underflow"
	case PrecompiledError:
		message = "precompiled error"
	case RevertInstruction:
		message = "revert instruction"
	case ContractAddressAlreadyUsed:
		message = "contract address already used"
	case PermissionDenied:
		message = "permission denied"
	case CallAddressError:
		message = "call address error"
	case GasOverflow:
		message = "gas overflow"
	case ContractFrozen:
		message = "contract frozen"
	case AccountFrozen:
		message = "account frozen"
	case AccountAbolished:
		message = "account abolished"
	case ContractAbolished:
		message = "contract abolished"
	case WASMValidationFailure:
		message = "WASM validation failure"
	case WASMArgumentOutOfRange:
		message = "WASM argument out of range"
	case WASMUnreachableInstruction:
		message = "WASM unreachable instruction"
	case WASMTrap:
		message = "WASM trap"
	case NonceCheckFail:
		message = "nonce check fail"
	case BlockLimitCheckFail:
		message = "block limit check fail"
	case TxPoolIsFull:
		message = "tx pool is full"
	case Malformed:
		message = "malformed"
	case AlreadyInTxPool:
		message = "already in tx pool"
	case TxAlreadyInChain:
		message = "tx already in chain"
	case InvalidChainId:
		message = "invalid chain id"
	case InvalidGroupId:
		message = "invalid group id"
	case InvalidSignature:
		message = "invalid signature"
	case RequestNotBelongToTheGroup:
		message = "request not belong to the group"
	case TransactionPoolTimeout:
		message = "transaction pool timeout"
	case AlreadyInTxPoolAndAccept:
		message = "already in tx pool and accept"
	default:
		message = strconv.Itoa(status)
	}

	return message
}

// GetBlockNumber returns the block number string
func (r *Receipt) GetBlockNumber() int {
	return r.BlockNumber
}

// GetContractAddress returns the contract address
func (r *Receipt) GetContractAddress() string {
	return r.ContractAddress
}

// GetFrom returns the transaction sender address
func (r *Receipt) GetFrom() string {
	return r.From
}

// GetGasUsed returns the used gas
func (r *Receipt) GetGasUsed() string {
	return r.GasUsed
}

func (r *Receipt) GetHash() string {
	return r.Hash
}

// GetInput returns the transaction content
func (r *Receipt) GetInput() string {
	return r.Input
}

// GetTransactionHash returns the transaction hash string
func (r *Receipt) GetTransactionHash() string {
	return r.TransactionHash
}

// GetOutput returns the transaction output
func (r *Receipt) GetOutput() string {
	return r.Output
}

// GetTransactionIndex returns the transaction index string
func (r *Receipt) GetReceiptProof() []string {
	return r.ReceiptProof
}

// GetStatus returns the transaction status
func (r *Receipt) GetStatus() int {
	return r.Status
}

// GetTo returns the transaction receiver address
func (r *Receipt) GetTo() string {
	return r.To
}

// GetTo returns the transaction receiver address
func (r *Receipt) GetVersion() uint64 {
	return r.Version
}

// ParseErrorMessage gets unusual output value from Receipt
func (r *Receipt) GetErrorMessage() string {
	var errorMessage string
	if r.GetStatus() == Success {
		return ""
	}
	errorMessage = getStatusMessage(r.Status)
	if len(r.Output) >= 138 { // 0x + 4 bytes funcName + 32 bytes offset + 32 bytes string length
		outputBytes, err := hex.DecodeString(r.Output[2:])
		if err != nil {
			panic(fmt.Sprintf("GetErrorMessage failed, hex.DecodeString err: %v", err))
		}
		errorMessage += ", " + string(outputBytes[68:])
		return fmt.Sprintf("receipt error code: %v, receipt error message: %v", r.Status, errorMessage)
	}
	return fmt.Sprintf("receipt error code: %v, receipt error message: %v", r.Status, errorMessage)
}

// String returns the string representation of Receipt struct.
func (r *Receipt) String() string {
	out, err := json.MarshalIndent(r, "", "\t")
	if err != nil {
		return fmt.Sprintf("%v", err)
	}
	return string(out)
}
