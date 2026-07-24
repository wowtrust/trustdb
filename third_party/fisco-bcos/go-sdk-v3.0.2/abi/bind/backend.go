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

	"github.com/FISCO-BCOS/go-sdk/v3/types"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
)

var (
	// ErrNoCode is returned by call and transact operations for which the requested
	// recipient contract to operate on does not exist in the state db or does not
	// have any code associated with it (i.e. suicided).
	ErrNoCode = errors.New("no contract code at given address")

	// This error is raised when attempting to perform a pending state action
	// on a backend that doesn't implement PendingContractCaller.
	ErrNoPendingState = errors.New("backend does not support pending state")

	// This error is returned by WaitDeployed if contract creation leaves an
	// empty contract behind.
	ErrNoCodeAfterDeploy = errors.New("no contract code after deployment")
)

// ContractCaller defines the methods needed to allow operating with contract on a read
// only basis.
type ContractCaller interface {
	// CodeAt returns the code of the given account. This is needed to differentiate
	// between contract internal errors and the local chain being out of sync.
	CodeAt(ctx context.Context, contract common.Address) ([]byte, error)
	// ContractCall executes a Solidity contract call with the specified data as the
	// input.
	CallContract(ctx context.Context, call ethereum.CallMsg) ([]byte, error)
}

// ContractTransactor defines the methods needed to allow operating with contract
// on a write only basis. Beside the transacting method, the remainder are helpers
// used when the user does not provide some needed values, but rather leaves it up
// to the transactor to decide.
type ContractTransactor interface {
	// PendingCodeAt returns the code of the given account in the pending state.
	PendingCodeAt(ctx context.Context, account common.Address) ([]byte, error)
	// SendTransaction injects the transaction into the pending pool for execution.
	SendTransaction(ctx context.Context, tx *types.Transaction) (*types.Receipt, error)
	AsyncSendTransaction(ctx context.Context, tx *types.Transaction, handler func(*types.Receipt, error)) error
	// GetGroupID returns the groupID of the client
	GetGroupID() string
	// GetChainID returns the chainID of the blockchain
	GetChainID(ctx context.Context) (string, error)
	// GetContractAddress returns the contract address once it was deployed
	GetContractAddress(ctx context.Context, txHash common.Hash) (common.Address, error)
	// SMCrypto returns true if use sm crypto
	SMCrypto() bool
}

// ContractFilterer defines the methods needed to access log events using one-off
// queries or continuous event subscriptions.
type ContractFilterer interface {
	// SubscribeEventLogs creates a background log filtering operation, returning
	// a subscription immediately, which can be used to stream the found events.
	SubscribeEventLogs(ctx context.Context, eventLogParams types.EventLogParams, handler func(int, []types.Log)) (string, error)
	UnSubscribeEventLogs(ctx context.Context, filterID string) error
}

// DeployBackend wraps the operations needed by WaitMined and WaitDeployed.
type DeployBackend interface {
	TransactionReceipt(ctx context.Context, txHash common.Hash) (*types.Receipt, error)
	CodeAt(ctx context.Context, account common.Address) ([]byte, error)
}

// ContractBackend defines the methods needed to work with contracts on a read-write basis.
type ContractBackend interface {
	ContractCaller
	ContractTransactor
	ContractFilterer
}
