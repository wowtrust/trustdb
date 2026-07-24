// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package bind

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/FISCO-BCOS/go-sdk/v3/abi"
	"github.com/FISCO-BCOS/go-sdk/v3/types"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
)

// SignerFn is a signer function callback when a contract requires a method to
// sign the transaction before submission.
type SignerFn func(types.Signer, common.Address, *types.Transaction) (*types.Transaction, error)

// CallOpts is the collection of options to fine tune a contract call request.
type CallOpts struct {
	Pending     bool            // Whether to operate on the pending state or the last known one
	From        common.Address  // Optional the sender address, otherwise the first account is used
	BlockNumber *big.Int        // Optional the block number on which the call should be performed
	Context     context.Context // Network context to support cancellation and timeouts (nil = no timeout)
}

// TransactOpts is the collection of authorization data required to create a
// valid Ethereum transaction.
type TransactOpts struct {
	From   common.Address // Ethereum account to send the transaction from
	Nonce  *big.Int       // Nonce to use for the transaction execution (nil = use pending state)
	Signer SignerFn       // Method to use for signing the transaction (mandatory)

	Value    *big.Int        // Funds to transfer along along the transaction (nil = 0 = no funds)
	GasPrice *big.Int        // Gas price to use for the transaction execution (nil = gas price oracle)
	GasLimit *big.Int        // Gas limit to set for the transaction execution (0 = estimate)
	Context  context.Context // Network context to support cancellation and timeouts (nil = no timeout)
}

// FilterOpts is the collection of options to fine tune filtering for events
// within a bound contract.
type FilterOpts struct {
	Start uint64  // Start of the queried range
	End   *uint64 // End of the range (nil = latest)

	Context context.Context // Network context to support cancellation and timeouts (nil = no timeout)
}

// WatchOpts is the collection of options to fine tune subscribing for events
// within a bound contract.
type WatchOpts struct {
	Start   *uint64         // Start of the queried range (nil = latest)
	Context context.Context // Network context to support cancellation and timeouts (nil = no timeout)
}

// BoundContract is the base wrapper object that reflects a contract on the
// Ethereum network. It contains a collection of methods that are used by the
// higher level contract bindings to operate.
type BoundContract struct {
	address    common.Address     // Deployment address of the contract on the Ethereum blockchain
	abi        abi.ABI            // Reflect based ABI to access the correct Ethereum methods
	caller     ContractCaller     // Read interface to interact with the blockchain
	transactor ContractTransactor // Write interface to interact with the blockchain
	filterer   ContractFilterer   // Event filtering to interact with the blockchain
}

// NewBoundContract creates a low level contract interface through which calls
// and transactions may be made through.
func NewBoundContract(address common.Address, abi abi.ABI, caller ContractCaller, transactor ContractTransactor, filterer ContractFilterer) *BoundContract {
	if transactor.SMCrypto() {
		abi.SetSMCrypto()
	}
	return &BoundContract{
		address:    address,
		abi:        abi,
		caller:     caller,
		transactor: transactor,
		filterer:   filterer,
	}
}

// DeployContract deploys a contract onto the Ethereum blockchain and binds the
// deployment address with a Go wrapper.
func DeployContract(opts *TransactOpts, abi abi.ABI, bytecode []byte, abiStr string, backend ContractBackend, params ...interface{}) (common.Address, *types.Receipt, *BoundContract, error) {
	_, receipt, c, err := deploy(opts, abi, bytecode, abiStr, backend, params...)
	addr := common.Address{}
	if receipt != nil && err == nil {
		if receipt.Status == types.Success {
			addr = common.HexToAddress(receipt.ContractAddress)
			return addr, receipt, c, nil
		} else {
			return addr, receipt, c, fmt.Errorf("deploy failed, receipt status: %d, message: %s", receipt.Status, receipt.GetErrorMessage())
		}
	}
	return addr, nil, nil, err
}

func DeployContractGetReceipt(opts *TransactOpts, abi abi.ABI, bytecode []byte, abiStr string, backend ContractBackend, params ...interface{}) (*types.Transaction, *types.Receipt, *BoundContract, error) {
	tx, receipt, c, err := deploy(opts, abi, bytecode, abiStr, backend, params...)
	return tx, receipt, c, err
}

func deploy(opts *TransactOpts, abi abi.ABI, bytecode []byte, abiStr string, backend ContractBackend, params ...interface{}) (*types.Transaction, *types.Receipt, *BoundContract, error) {
	c := NewBoundContract(common.Address{}, abi, backend, backend, backend)
	input, err := c.abi.Pack("", params...)
	if err != nil {
		return nil, nil, nil, err
	}
	tx, receipt, err := c.transact(opts, nil, append(bytecode, input...), abiStr)
	if err != nil {
		return nil, nil, nil, err
	}
	if receipt == nil {
		return nil, nil, nil, errors.New("deploy failed, receipt is nil")
	}
	c.address = common.HexToAddress(receipt.ContractAddress)
	return tx, receipt, c, nil
}

func AsyncDeployContract(opts *TransactOpts, handler func(*types.Receipt, error), abi abi.ABI, bytecode []byte, abiStr string, backend ContractBackend, params ...interface{}) (*types.Transaction, error) {
	// Otherwise try to deploy the contract
	c := NewBoundContract(common.Address{}, abi, backend, backend, backend)

	input, err := c.abi.Pack("", params...)
	if err != nil {
		return nil, err
	}
	return c.asyncTransact(opts, nil, append(bytecode, input...), abiStr, handler)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (c *BoundContract) Call(opts *CallOpts, result interface{}, method string, params ...interface{}) error {
	// Don't crash on a lazy user
	if opts == nil {
		opts = new(CallOpts)
	}

	// Pack the input, call and unpack the results
	input, err := c.abi.Pack(method, params...)
	if err != nil {
		return err
	}
	var (
		msg    = ethereum.CallMsg{From: opts.From, To: &c.address, Data: input}
		ctx    = ensureContext(opts.Context)
		code   []byte
		output []byte
	)
	output, err = c.caller.CallContract(ctx, msg)
	if err == nil && len(output) == 0 {
		// Make sure we have a contract to operate on, and bail out otherwise.
		if code, err = c.caller.CodeAt(ctx, c.address); err != nil {
			return err
		} else if len(code) == 0 {
			return ErrNoCode
		}
	}
	if err != nil {
		return err
	}
	return c.abi.Unpack(result, method, output)
}

// TransactWithResult invokes the (paid) contract method with params as input values.
func (c *BoundContract) TransactWithResult(opts *TransactOpts, result interface{}, method string, params ...interface{}) (*types.Transaction, *types.Receipt, error) {
	// Otherwise pack up the parameters and invoke the contract
	input, err := c.abi.Pack(method, params...)
	if err != nil {
		return nil, nil, err
	}
	tx, receipt, err := c.transact(opts, &c.address, input, "")
	if err != nil {
		return tx, receipt, err
	}
	if receipt.Status != types.Success {
		return tx, receipt, fmt.Errorf("transact failed, receipt status: %d, message: %s", receipt.Status, receipt.GetErrorMessage())
	}
	err = c.abi.Unpack(result, method, common.FromHex(receipt.GetOutput()))
	if err != nil {
		return tx, receipt, err
	}
	return tx, receipt, err
}

// Transact invokes the (paid) contract method with params as input values.
func (c *BoundContract) Transact(opts *TransactOpts, method string, params ...interface{}) (*types.Transaction, *types.Receipt, error) {
	// Otherwise pack up the parameters and invoke the contract
	input, err := c.abi.Pack(method, params...)
	if err != nil {
		return nil, nil, err
	}
	return c.transact(opts, &c.address, input, "")
}

func (c *BoundContract) AsyncTransact(opts *TransactOpts, handler func(*types.Receipt, error), method string, params ...interface{}) (*types.Transaction, error) {
	// Otherwise pack up the parameters and invoke the contract
	input, err := c.abi.Pack(method, params...)
	if err != nil {
		return nil, err
	}
	return c.asyncTransact(opts, &c.address, input, "", handler)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (c *BoundContract) Transfer(opts *TransactOpts) (*types.Transaction, *types.Receipt, error) {
	return c.transact(opts, &c.address, nil, "")
}

// transact executes an actual transaction invocation, first deriving any missing
// authorization fields, and then scheduling the transaction for execution.
func (c *BoundContract) transact(opts *TransactOpts, contract *common.Address, input []byte, abi string) (*types.Transaction, *types.Receipt, error) {
	var receipt *types.Receipt
	var err error
	tx := types.NewSimpleTx(contract, input, abi, "", "", c.transactor.SMCrypto())
	if receipt, err = c.transactor.SendTransaction(ensureContext(opts.Context), tx); err != nil {
		return nil, nil, err
	}
	return nil, receipt, nil
}

func (c *BoundContract) asyncTransact(opts *TransactOpts, contract *common.Address, input []byte, abi string, handler func(*types.Receipt, error)) (*types.Transaction, error) {
	tx := types.NewSimpleTx(contract, input, abi, "", "", c.transactor.SMCrypto())
	if err := c.transactor.AsyncSendTransaction(ensureContext(opts.Context), tx, handler); err != nil {
		return nil, err
	}
	return nil, nil
}

// WatchLogs filters subscribes to contract logs for future blocks, returning a
// subscription object that can be used to tear down the watcher.
func (c *BoundContract) WatchLogs(fromBlock *int64, handler func(int, []types.Log), name string, query ...interface{}) (string, error) {
	from := int64(1)
	to := int64(-1)
	// Don't crash on a lazy user
	if fromBlock != nil {
		from = int64(*fromBlock)
	}
	// Append the event selector to the query parameters and construct the topic set
	query = append([]interface{}{c.abi.Events[name].ID()}, query...)

	topics, err := makeTopics(query...)
	if err != nil {
		return "", err
	}
	eventLogParams := types.EventLogParams{
		FromBlock: from,
		ToBlock:   to,
		Addresses: []string{strings.ToLower(c.address.Hex())},
		Topics:    topics,
	}
	return c.filterer.SubscribeEventLogs(context.Background(), eventLogParams, handler)
}

// UnpackLog unpacks a retrieved log into the provided output structure.
func (c *BoundContract) UnpackLog(out interface{}, event string, log types.Log) error {
	if len(log.Data) > 0 {
		if err := c.abi.Unpack(out, event, log.Data); err != nil {
			return err
		}
	}
	var indexed abi.Arguments
	for _, arg := range c.abi.Events[event].Inputs {
		if arg.Indexed {
			indexed = append(indexed, arg)
		}
	}
	return parseTopics(out, indexed, log.Topics[1:])
}

// UnpackLogIntoMap unpacks a retrieved log into the provided map.
func (c *BoundContract) UnpackLogIntoMap(out map[string]interface{}, event string, log types.Log) error {
	if len(log.Data) > 0 {
		if err := c.abi.UnpackIntoMap(out, event, log.Data); err != nil {
			return err
		}
	}
	var indexed abi.Arguments
	for _, arg := range c.abi.Events[event].Inputs {
		if arg.Indexed {
			indexed = append(indexed, arg)
		}
	}
	return parseTopicsIntoMap(out, indexed, log.Topics[1:])
}

// // ensureContext is a helper method to ensure a context is not nil, even if the
// // user specified it as such.
func ensureContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.TODO()
	}
	return ctx
}
