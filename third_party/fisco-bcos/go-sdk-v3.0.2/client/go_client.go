// Copyright FISCO-BCOS go-sdk
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package client provides a client for the FISCO BCOS RPC API.
package client

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"strings"

	"github.com/FISCO-BCOS/go-sdk/v3/abi/bind"
	"github.com/FISCO-BCOS/go-sdk/v3/types"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// Client defines typed wrappers for the Ethereum RPC API.
type Client struct {
	conn     *Connection
	groupID  string
	chainID  string
	auth     *bind.TransactOpts
	callOpts *bind.CallOpts
	smCrypto bool
}

const (
	indent           = "  "
	BlockLimit int64 = 600
)

// Dial connects a client to the given URL and groupID.
func Dial(configFile, groupID string, privateKey []byte) (*Client, error) {
	if len(privateKey) == 0 {
		return nil, errors.New("private key is empty")
	}
	c, err := NewConnectionByFile(configFile, groupID, privateKey)
	if err != nil {
		return nil, err
	}
	return newClient(c)
}

// DialContext pass the context to the rpc client
func DialContext(ctx context.Context, config *Config) (*Client, error) {
	if config == nil {
		return nil, errors.New("config is nil")
	}
	if len(config.PrivateKey) == 0 {
		return nil, errors.New("private key is empty")
	}
	c, err := NewConnection(config)
	if err != nil {
		return nil, err
	}
	return newClient(c)
}

func newClient(c *Connection) (*Client, error) {
	sdk := c.GetCSDK()
	if sdk.WASM() {
		return nil, errors.New("wasm is not supported for now")
	}
	client := Client{conn: c, groupID: sdk.GroupID(), chainID: sdk.ChainID(), smCrypto: sdk.SMCrypto()}
	if sdk.SMCrypto() {
		client.auth = bind.NewSMCryptoTransactor(sdk.PrivateKeyBytes())
	} else {
		privateKey, err := crypto.ToECDSA(sdk.PrivateKeyBytes())
		if err != nil {
			return nil, fmt.Errorf("new client errors failed: %v", err)
		}
		client.auth = bind.NewKeyedTransactor(privateKey)
	}
	client.auth.GasLimit = big.NewInt(30000000)
	client.callOpts = &bind.CallOpts{From: client.auth.From}
	return &client, nil
}

// Close disconnects the rpc
func (c *Client) Close() {
	c.conn.Close()
}

// ============================================== FISCO BCOS Blockchain Access ================================================

func toCallArg(msg ethereum.CallMsg) interface{} {
	arg := map[string]interface{}{
		"from": msg.From.String(),
		"to":   strings.ToLower(msg.To.String()[2:]),
	}
	if len(msg.Data) > 0 {
		arg["data"] = hex.EncodeToString(msg.Data)
	}
	if msg.Value != nil {
		arg["value"] = fmt.Sprintf("%#x", msg.Value)
	}

	if msg.Gas != 0 {
		arg["gas"] = fmt.Sprintf("%#x", msg.Gas)
	}
	if msg.GasPrice != nil {
		arg["gasPrice"] = fmt.Sprintf("%#x", msg.GasPrice)
	}

	return arg
}

type callResult struct {
	CurrentBlockNumber int    `json:"currentBlockNumber"`
	Output             string `json:"output"`
	Status             int    `json:"status"`
}

// GetTransactOpts return *bind.TransactOpts
func (c *Client) GetTransactOpts() *bind.TransactOpts {
	return c.auth
}

// SetTransactOpts set auth
func (c *Client) SetTransactOpts(opts *bind.TransactOpts) {
	c.auth = opts
}

// SetCallOpts set call opts
func (c *Client) SetCallOpts(opts *bind.CallOpts) {
	c.callOpts = opts
}

// GetCallOpts return *bind.CallOpts
func (c *Client) GetCallOpts() *bind.CallOpts {
	return c.callOpts
}

// SMCrypto returns true if use sm crypto
func (c *Client) SMCrypto() bool {
	return c.conn.GetCSDK().SMCrypto()
}

// CodeAt returns the contract code of the given account.
// The block number can be nil, in which case the code is taken from the latest known block.
func (c *Client) CodeAt(ctx context.Context, address common.Address) ([]byte, error) {
	var raw interface{}
	err := c.conn.CallContext(ctx, &raw, "getCode", address.Hex())
	if err != nil {
		return nil, err
	}
	js, err := json.MarshalIndent(raw, "", indent)
	return js, err
}

func (c *Client) GetABI(ctx context.Context, address common.Address) (string, error) {
	req, err := c.conn.NewMessage("getABI", c.groupID, "", address.Hex())
	if err != nil {
		return "", err
	}
	message, err := json.Marshal(req)
	if err != nil {
		return "", err
	}
	response, err := c.conn.sendRPCRequest(c.groupID, "", string(message))
	if err != nil {
		return "", err
	}
	return string(response.Result), nil
}

// PendingCodeAt returns the contract code of the given account in the pending state.
func (c *Client) PendingCodeAt(ctx context.Context, address common.Address) ([]byte, error) {
	var raw interface{}
	err := c.conn.CallContext(ctx, &raw, "getCode", address.Hex())
	if err != nil {
		return nil, err
	}
	js, err := json.MarshalIndent(raw, "", indent)
	return js, err
}

// CallContract invoke the call method of rpc api
func (c *Client) CallContract(ctx context.Context, msg ethereum.CallMsg) ([]byte, error) {
	var hexBytes []byte
	var cr *callResult
	err := c.conn.CallContext(ctx, &cr, "call", toCallArg(msg))
	if err != nil {
		return nil, err
	}
	if cr.Status != 0 {
		var errorMessage string
		if len(cr.Output) >= 138 {
			outputBytes := common.FromHex(cr.Output)
			errorMessage = string(outputBytes[68:])
		}
		return nil, fmt.Errorf("call error of status %d, %v", cr.Status, errorMessage)
	}
	hexBytes = common.FromHex(cr.Output)
	return hexBytes, nil
}

// SendTransaction injects a signed transaction into the pending pool for execution.
//
// If the transaction was a contract creation use the TransactionReceipt method to get the
// contract address after the transaction has been mined.
func (c *Client) SendTransaction(ctx context.Context, tx *types.Transaction) (*types.Receipt, error) {
	var err error
	var anonymityReceipt = &struct {
		types.Receipt
	}{}
	if tx.To() != nil {
		err = c.conn.CallContext(ctx, anonymityReceipt, "sendTransaction", tx.Input(), strings.ToLower(tx.To().String()))
	} else {
		err = c.conn.CallContext(ctx, anonymityReceipt, "sendTransaction", tx.Input(), "", tx.ABI())
	}
	if err != nil {
		errorStr := fmt.Sprintf("%s", err)
		if strings.Contains(errorStr, "connection refused") {
			log.Println("connection refused err:", err)
			return nil, err
		}
		return nil, err
	}
	return &anonymityReceipt.Receipt, nil
}

// AsyncSendTransaction send transaction async
func (c *Client) AsyncSendTransaction(ctx context.Context, tx *types.Transaction, handler func(*types.Receipt, error)) error {
	var err error
	var anonymityReceipt = &struct {
		types.Receipt
	}{}
	if tx.To() != nil {
		err = c.conn.CallContext(ctx, anonymityReceipt, "asyncSendTransaction", tx.Input(), strings.ToLower(tx.To().String()), handler)
	} else {
		err = c.conn.CallContext(ctx, anonymityReceipt, "asyncSendTransaction", tx.Input(), "", handler, tx.ABI())
	}
	if err != nil {
		return err
	}
	// handler(&anonymityReceipt.Receipt, nil)
	return nil
}

func (c *Client) CreateEncodedTransactionDataV1(to *common.Address, input []byte, blockLimit int64, abi string) ([]byte, []byte, error) {
	addressHex := ""
	if to != nil {
		addressHex = strings.ToLower(to.String()[2:])
	}
	return c.conn.GetCSDK().CreateEncodedTransactionDataV1(blockLimit, addressHex, input, abi)
}

func (c *Client) CreateEncodedSignature(hash []byte) ([]byte, error) {
	return c.conn.GetCSDK().CreateEncodedSignature(hash)
}

func (c *Client) CreateEncodedTransaction(transactionData, transactionDataHash, signature []byte, attribute int32, extraData string) ([]byte, error) {
	return c.conn.GetCSDK().CreateEncodedTransaction(transactionData, transactionDataHash, signature, attribute, extraData)
}

func (c *Client) SendEncodedTransaction(ctx context.Context, encodedTransaction []byte, withProof bool) (*types.Receipt, error) {
	var err error
	var anonymityReceipt = &struct {
		types.Receipt
	}{}
	err = c.conn.CallContext(ctx, anonymityReceipt, "SendEncodedTransaction", encodedTransaction, withProof)
	if err != nil {
		errorStr := fmt.Sprintf("%s", err)
		if strings.Contains(errorStr, "connection refused") {
			log.Println("connection refused err:", err)
			return nil, err
		}
		return nil, err
	}
	return &anonymityReceipt.Receipt, nil
}

func (c *Client) AsyncSendEncodedTransaction(ctx context.Context, encodedTransaction []byte, withProof bool, handler func(*types.Receipt, error)) error {
	err := c.conn.CallContext(ctx, nil, "SendEncodedTransaction", encodedTransaction, withProof, handler)
	if err != nil {
		errorStr := fmt.Sprintf("%s", err)
		if strings.Contains(errorStr, "connection refused") {
			log.Println("connection refused err:", err)
			return err
		}
		return err
	}
	return nil
}

func (c *Client) SetPrivateKey(privateKey []byte) error {
	return c.conn.GetCSDK().SetPrivateKey(privateKey)
}

func (c *Client) PrivateKeyBytes() []byte {
	return c.conn.GetCSDK().PrivateKeyBytes()
}

// TransactionReceipt returns the receipt of a transaction by transaction hash.
// Note that the receipt is not available for pending transactions.
func (c *Client) TransactionReceipt(ctx context.Context, txHash common.Hash) (*types.Receipt, error) {
	return c.GetTransactionReceipt(ctx, txHash, true)
}

func (c *Client) SubscribeEventLogs(ctx context.Context, eventLogParams types.EventLogParams, handler func(int, []types.Log)) (string, error) {
	return c.conn.SubscribeEventLogs(eventLogParams, handler)
}

func (c *Client) UnSubscribeEventLogs(ctx context.Context, taskId string) error {
	c.conn.UnsubscribeEventLogs(taskId)
	return nil
}

func (c *Client) SubscribeAmopTopic(ctx context.Context, topic string, handler func([]byte, *[]byte)) error {
	return c.conn.SubscribeAmopTopic(topic, handler)
}

func (c *Client) PublishAmopTopicMessage(ctx context.Context, topic string, data []byte, handler func([]byte, error)) error {
	return c.conn.PublishAmopTopicMessage(ctx, topic, data, handler)
}

func (c *Client) SendAmopResponse(peer, seq string, data []byte) error {
	c.conn.SendAmopResponse(peer, seq, data)
	return nil
}

func (c *Client) BroadcastAMOPMsg(topic string, data []byte) error {
	c.conn.BroadcastAmopMsg(topic, data)
	return nil
}

func (c *Client) UnsubscribeAmopTopic(topic string) error {
	c.conn.UnsubscribeAmopTopic(topic)
	return nil
}

func (c *Client) SubscribeBlockNumberNotify(ctx context.Context, handler func(int64)) error {
	return c.conn.SubscribeBlockNumberNotify(handler)
}

func (c *Client) UnsubscribeBlockNumberNotify() {
	c.conn.UnsubscribeBlockNumberNotify()
}

// GetGroupID returns the groupID of the client
func (c *Client) GetGroupID() string {
	return c.groupID
}

// SetGroupID sets the groupID of the client
func (c *Client) SetGroupID(newID string) {
	c.groupID = newID
}

// GetChainID returns the Chain ID of the FISCO BCOS running on the nodes.
func (c *Client) GetChainID(ctx context.Context) (string, error) {
	return c.chainID, nil
}

// GetBlockNumber returns the latest block height(hex format) on a given groupID.
func (c *Client) GetBlockNumber(ctx context.Context) (int64, error) {
	var raw int64
	err := c.conn.CallContext(ctx, &raw, "getBlockNumber")
	if err != nil {
		return -1, err
	}
	return raw, err
}

// GetPBFTView returns the latest PBFT view(hex format) of the specific group and it will returns a wrong sentence
func (c *Client) GetPBFTView(ctx context.Context) ([]byte, error) {
	var raw interface{}
	err := c.conn.CallContext(ctx, &raw, "getPbftView")
	if err != nil {
		return nil, err
	}
	js, err := json.MarshalIndent(raw, "", indent)
	return js, err
}

type ConsensusNodeInfo struct {
	ID     string `json:"nodeID"`
	Weight uint   `json:"weight"`
}

// GetSealerList returns the list of consensus nodes' ID according to the groupID
func (c *Client) GetSealerList(ctx context.Context) ([]ConsensusNodeInfo, error) {
	var raw []ConsensusNodeInfo
	err := c.conn.CallContext(ctx, &raw, "getSealerList")
	if err != nil {
		return nil, err
	}
	return raw, err
}

// GetObserverList returns the list of observer nodes' ID according to the groupID
func (c *Client) GetObserverList(ctx context.Context) ([]string, error) {
	var raw []string
	err := c.conn.CallContext(ctx, &raw, "getObserverList")
	if err != nil {
		return nil, err
	}
	return raw, err
}

// GetConsensusStatus returns the status information about the consensus algorithm on a specific groupID
func (c *Client) GetConsensusStatus(ctx context.Context) ([]byte, error) {
	var raw interface{}
	err := c.conn.CallContext(ctx, &raw, "getConsensusStatus")
	if err != nil {
		return nil, err
	}
	js, err := json.MarshalIndent(raw, "", indent)
	return js, err
}

// GetSyncStatus returns the synchronization status of the group
func (c *Client) GetSyncStatus(ctx context.Context) (*types.SyncStatus, error) {
	var syncStatus types.SyncStatus
	var raw interface{}
	err := c.conn.CallContext(ctx, &raw, "getSyncStatus")
	if err != nil {
		return nil, err
	}
	js := strings.Replace(raw.(string), "\\", "", -1)
	json.Unmarshal([]byte(js), &syncStatus)
	return &syncStatus, err
}

// GetPeers returns the information of the connected peers
func (c *Client) GetPeers(ctx context.Context) ([]byte, error) {
	var raw interface{}
	err := c.conn.CallContext(ctx, &raw, "getPeers")
	if err != nil {
		return nil, err
	}
	js, err := json.MarshalIndent(raw, "", indent)
	return js, err
}

// GetGroupPeers returns the nodes and the observer nodes list on a specific group
func (c *Client) GetGroupPeers(ctx context.Context) ([]byte, error) {
	var raw interface{}
	err := c.conn.CallContext(ctx, &raw, "getGroupPeers")
	if err != nil {
		return nil, err
	}
	js, err := json.MarshalIndent(raw, "", indent)
	return js, err
}

// GetNodeIDList returns the ID information of the connected peers and itself
func (c *Client) GetNodeIDList(ctx context.Context) ([]byte, error) {
	var raw interface{}
	err := c.conn.CallContext(ctx, &raw, "getNodeIDList")
	if err != nil {
		return nil, err
	}
	js, err := json.MarshalIndent(raw, "", indent)
	return js, err

}

// GetGroupInfoList returns the ID information of the connected peers and itself
func (c *Client) GetGroupInfoList(ctx context.Context) ([]byte, error) {
	var raw interface{}
	err := c.conn.CallContext(ctx, &raw, "getGroupInfoList")
	if err != nil {
		return nil, err
	}
	js, err := json.MarshalIndent(raw, "", indent)
	return js, err
}

// GetGroupList returns the groupID list that the node belongs to
func (c *Client) GetGroupList(ctx context.Context) ([]byte, error) {
	var raw interface{}
	err := c.conn.CallContext(ctx, &raw, "getGroupList")
	if err != nil {
		return nil, err
	}
	js, err := json.MarshalIndent(raw, "", indent)
	return js, err
}

// GetBlockByHash returns the block information according to the given block hash
func (c *Client) GetBlockByHash(ctx context.Context, blockHash common.Hash, onlyHeader, onlyTxHash bool) (*types.Block, error) {
	var block types.Block
	err := c.conn.CallContext(ctx, &block, "getBlockByHash", blockHash.Hex(), onlyHeader, onlyTxHash)
	if err != nil {
		return nil, err
	}
	return &block, err
}

// GetBlockByNumber returns the block information according to the given block number(hex format)
func (c *Client) GetBlockByNumber(ctx context.Context, blockNumber int64, onlyHeader, onlyTxHash bool) (*types.Block, error) {
	var block types.Block
	if blockNumber < 0 {
		return nil, errors.New("invalid negative block number")
	}
	err := c.conn.CallContext(ctx, &block, "getBlockByNumber", blockNumber, onlyHeader, onlyTxHash)
	if err != nil {
		return nil, err
	}
	return &block, err
}

// GetBlockHashByNumber returns the block hash according to the given block number
func (c *Client) GetBlockHashByNumber(ctx context.Context, blockNumber int64) (*common.Hash, error) {
	if blockNumber < 0 {
		return nil, errors.New("invalid negative block number")
	}
	var raw string
	err := c.conn.CallContext(ctx, &raw, "getBlockHashByNumber", blockNumber)
	if err != nil {
		return nil, err
	}
	blockHash := common.HexToHash(raw)
	return &blockHash, err
}

// GetTransactionByHash returns the transaction information according to the given transaction hash
func (c *Client) GetTransactionByHash(ctx context.Context, txHash common.Hash, withProof bool) (*types.TransactionDetail, error) {
	var transactionDetail types.TransactionDetail
	err := c.conn.CallContext(ctx, &transactionDetail, "getTransactionByHash", txHash.String(), withProof)
	if err != nil {
		return nil, err
	}
	return &transactionDetail, err
}

// GetTransactionReceipt returns the transaction receipt according to the given transaction hash
func (c *Client) GetTransactionReceipt(ctx context.Context, txHash common.Hash, withProof bool) (*types.Receipt, error) {
	var raw *types.Receipt
	var anonymityReceipt = &struct {
		types.Receipt
	}{}
	err := c.conn.CallContext(ctx, anonymityReceipt, "getTransactionReceipt", txHash.String(), withProof)
	if err != nil {
		return nil, err
	}
	//if len(anonymityReceipt.Status) < 2 {
	//	return nil, fmt.Errorf("transaction %v is not on-chain", txHash.Hex())
	//}
	//status, err := strconv.ParseInt(anonymityReceipt.Status[2:], 16, 32)
	//if err != nil {
	//	return nil, fmt.Errorf("GetTransactionReceipt failed, strconv.ParseInt err: " + fmt.Sprint(err))
	//}
	raw = &anonymityReceipt.Receipt
	//raw.Status = int(status)
	return raw, err
}

// GetContractAddress returns a contract address according to the transaction hash
func (c *Client) GetContractAddress(ctx context.Context, txHash common.Hash) (common.Address, error) {
	var raw interface{}
	var contractAddress common.Address
	err := c.conn.CallContext(ctx, &raw, "getTransactionReceipt", txHash.Hex(), false)
	if err != nil {
		return contractAddress, err
	}
	m, ok := raw.(map[string]interface{})
	if !ok {
		return contractAddress, fmt.Errorf("GetContractAddress Json respond does not satisfy the type assertion: map[string]interface{}, %+v", raw)
	}
	var temp interface{}
	temp, ok = m["contractAddress"]
	if !ok {
		return contractAddress, errors.New("json respond does not contains the key `contractAddress`")
	}
	var strContractAddress string
	strContractAddress, ok = temp.(string)
	if !ok {
		return contractAddress, errors.New("type assertion for Chain Id is wrong: not a string")
	}
	return common.HexToAddress(strContractAddress), nil
}

// GetPendingTxSize returns amount of the pending transactions
func (c *Client) GetPendingTxSize(ctx context.Context) (int64, error) {
	var raw int64
	err := c.conn.CallContext(ctx, &raw, "getPendingTxSize")
	if err != nil {
		return 0, err
	}
	return raw, err
}

// GetCode returns the contract code according to the contract address
func (c *Client) GetCode(ctx context.Context, address common.Address) ([]byte, error) {
	var raw interface{}
	err := c.conn.CallContext(ctx, &raw, "getCode", strings.ToLower(address.String()[2:]))
	if err != nil {
		return nil, err
	}
	js, err := json.MarshalIndent(raw, "", indent)
	return js, err
}

// GetTotalTransactionCount returns the total amount of transactions and the block height at present
func (c *Client) GetTotalTransactionCount(ctx context.Context) (*types.TransactionCount, error) {
	var transactionCount types.TransactionCount
	err := c.conn.CallContext(ctx, &transactionCount, "getTotalTransactionCount")
	if err != nil {
		return nil, err
	}
	return &transactionCount, err
}

func (c *Client) GetNodeInfo(ctx context.Context, nodeId string) ([]byte, error) {
	var raw interface{}
	err := c.conn.CallContext(ctx, &raw, "getNodeInfo", nodeId)
	if err != nil {
		return nil, err
	}
	js, err := json.MarshalIndent(raw, "", indent)
	return js, err
}

func (c *Client) GetGroupInfo(ctx context.Context) ([]byte, error) {
	var raw interface{}
	err := c.conn.CallContext(ctx, &raw, "getGroupInfo")
	if err != nil {
		return nil, err
	}
	js, err := json.MarshalIndent(raw, "", indent)
	return js, err
}

// GetSystemConfigByKey returns value according to the key(only tx_count_limit, tx_gas_limit could work)
func (c *Client) GetSystemConfigByKey(ctx context.Context, configKey string) (*types.SystemConfig, error) {
	var raw types.SystemConfig
	err := c.conn.CallContext(ctx, &raw, "getSystemConfigByKey", configKey)
	if err != nil {
		return nil, err
	}
	//js, err := json.MarshalIndent(raw, "", indent)
	return &raw, err
}
