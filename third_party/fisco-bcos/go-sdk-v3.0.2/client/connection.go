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

package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/FISCO-BCOS/bcos-c-sdk/bindings/go/csdk"
	"github.com/FISCO-BCOS/go-sdk/v3/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/sirupsen/logrus"
)

var (
	ErrClientQuit                = errors.New("client is closed")
	ErrNoResult                  = errors.New("no result in JSON-RPC response")
	ErrNoRpcMethod               = errors.New("no rpc method")
	ErrSubscriptionQueueOverflow = errors.New("subscription queue overflow")
	errClientReconnected         = errors.New("client reconnected")
	errDead                      = errors.New("connection lost")
)

const (
	// Timeouts
	tcpKeepAliveInterval      = 30 * time.Second
	subscribeTimeout          = 5 * time.Second // overall timeout eth_subscribe, rpc_modules calls
	amopTimeout               = 1000
	cleanupInterval           = 15 * time.Minute
	defaultTransactionTimeout = 10 * time.Minute
	jsonRPCVersion            = "2.0"
)

// Error wraps RPC errors, which contain an error code in addition to the message.
type Error interface {
	Error() string  // returns the message
	ErrorCode() int // returns the code
}

// Connection represents a connection to an RPC server.
type Connection struct {
	csdk              *csdk.CSDK
	idCounter         int64
	blockNumberNotify func(int64)
	notifyLock        sync.Mutex
	closed            bool
	lock              sync.Mutex
}

type requestOp struct {
	ids          []json.RawMessage
	err          error
	respChanData *csdk.CallbackChan
	//handler      func(*types.Receipt, error)
}

type EventLogRespResult struct {
	LogIndex         int    `json:"logIndex"`
	TransactionIndex int    `json:"transactionIndex"`
	TransactionHash  string `json:"transactionHash"`
	//BlockHash        string   `json:"blockHash"`
	BlockNumber uint64   `json:"blockNumber"`
	Address     string   `json:"address"`
	Data        string   `json:"data"`
	Topics      []string `json:"topics"`
}

type eventLogResp struct {
	FilterID string               `json:"id"`
	Result   []EventLogRespResult `json:"result"`
	Status   int                  `json:"status"`
}

func (op *requestOp) waitRpcMessage(ctx context.Context) (*jsonrpcMessage, interface{}, error) {
	respBody, err := op.respChanData.Wait(ctx)
	if err != nil {
		return nil, nil, err
	}
	var respData jsonrpcMessage
	if respBody.Err == nil {
		if err := json.Unmarshal(respBody.Result.([]byte), &respData); err != nil {
			return nil, nil, err
		}
		return &respData, respData.Result, op.err
	}
	return nil, respBody.Result, respBody.Err
}

func processEventLogMsg(respBody []byte, handler interface{}) {
	var eventLogResponse eventLogResp
	err := json.Unmarshal(respBody, &eventLogResponse)
	if err != nil {
		logrus.Warnf("unmarshal eventLogResponse failed, err: %v\n", err)
		return
	}
	if len(eventLogResponse.Result) == 0 {
		return
	}
	logs := []types.Log{}
	for _, eventLog := range eventLogResponse.Result {
		number := eventLog.BlockNumber
		logIndex := eventLog.LogIndex
		txIndex := eventLog.TransactionIndex
		topics := []common.Hash{}
		for _, topic := range eventLog.Topics {
			topics = append(topics, common.HexToHash(topic))
		}
		data := common.FromHex(eventLog.Data)
		logs = append(logs, types.Log{
			Address:     common.HexToAddress(eventLog.Address),
			Topics:      topics,
			Data:        data,
			BlockNumber: uint64(number),
			TxHash:      common.HexToHash(eventLog.TransactionHash),
			TxIndex:     uint(txIndex),
			//BlockHash:   common.HexToHash(eventLog.BlockHash),
			Index: uint(logIndex),
			// Removed: false,
		})
	}
	handler.(func(int, []types.Log))(int(eventLogResponse.Status), logs)
}

func NewConnectionByFile(configFile, groupID string, privateKey []byte) (*Connection, error) {
	sdk, err := csdk.NewSDKByConfigFile(configFile, groupID, privateKey)
	if err != nil {
		return nil, err
	}
	c := &Connection{
		csdk: sdk,
	}
	return c, nil
}

func NewConnection(config *Config) (*Connection, error) {
	path, _ := os.Getwd()
	if !config.DisableSsl {
		if _, err := os.Stat(config.TLSCaFile); os.IsNotExist(err) {
			return nil, fmt.Errorf("the file %s does not exist, current working directory is %s", config.TLSCaFile, path)
		} else if _, err := os.Stat(config.TLSKeyFile); os.IsNotExist(err) {
			return nil, fmt.Errorf("the file %s does not exist, current working directory is %s", config.TLSKeyFile, path)
		} else if _, err := os.Stat(config.TLSCertFile); os.IsNotExist(err) {
			return nil, fmt.Errorf("the file %s does not exist, current working directory is %s", config.TLSCertFile, path)
		}
		if config.IsSMCrypto {
			if _, err := os.Stat(config.TLSSmEnKeyFile); os.IsNotExist(err) {
				return nil, fmt.Errorf("the file %s does not exist, current working directory is %s", config.TLSSmEnKeyFile, path)
			} else if _, err := os.Stat(config.TLSSmEnCertFile); os.IsNotExist(err) {
				return nil, fmt.Errorf("the file %s does not exist, current working directory is %s", config.TLSSmEnCertFile, path)
			}
		}
	}
	sdk, err := csdk.NewSDK(config.GroupID, config.Host, config.Port, config.IsSMCrypto, config.PrivateKey, config.DisableSsl, config.TLSCaFile, config.TLSKeyFile, config.TLSCertFile, config.TLSSmEnKeyFile, config.TLSSmEnCertFile)
	if err != nil {
		return nil, fmt.Errorf("new csdk failed: %v", err)
	}
	if err != nil {
		return nil, err
	}
	c := &Connection{
		csdk: sdk,
	}
	return c, nil
}
func (c *Connection) GetCSDK() *csdk.CSDK {
	return c.csdk
}

func wrapTransactionResponsesHandler(f func(*types.Receipt, error)) func([]byte, error) {
	return func(bytes []byte, err error) {
		var jrm jsonrpcMessage
		if err != nil {
			f(nil, err)
			return
		}
		if err = json.Unmarshal(bytes, &jrm); err != nil {
			f(nil, err)
			return
		}
		if jrm.Error != nil {
			f(nil, jrm.Error)
			return
		}
		if len(jrm.Result) == 0 {
			f(nil, errors.New("result is null"))
			return
		}
		var receipt types.Receipt
		err = json.Unmarshal(jrm.Result, &receipt)
		if err != nil {
			f(nil, fmt.Errorf("unmarshal receipt error: %v", err))
			return
		}
		f(&receipt, nil)
	}
}

func (c *Connection) nextID() int64 {
	id := atomic.AddInt64(&c.idCounter, 1)
	return id
}

func (c *Connection) NewMessage(method string, paramsIn ...interface{}) (*jsonrpcMessage, error) {
	msg := &jsonrpcMessage{Version: jsonRPCVersion, ID: c.nextID(), Method: method}
	if paramsIn != nil { // prevent sending "params":null
		var err error
		if msg.Params, err = json.Marshal(paramsIn); err != nil {
			return nil, err
		}
	}
	return msg, nil
}

// Close closes the client, aborting any in-flight requests.
func (c *Connection) Close() {
	if c.closed {
		return
	}
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.closed {
		return
	}
	c.closed = true
	c.csdk.Close()
}

func (c *Connection) SendAmopResponse(peer, seq string, data []byte) {
	c.csdk.SendAmopResponse(peer, seq, data)
}

func (c *Connection) UnsubscribeAmopTopic(topic string) {
	c.csdk.UnsubscribeAmopTopic(topic)
}

func (c *Connection) BroadcastAmopMsg(topic string, data []byte) {
	c.csdk.BroadcastAmopMsg(topic, data)
}

func (c *Connection) SubscribeEventLogs(eventLogParams types.EventLogParams, handler func(int, []types.Log)) (string, error) {
	sendData, err := json.Marshal(eventLogParams)
	if err != nil {
		return "", err
	}
	var sdkContext csdk.CallbackChan
	sdkContext.Handler = func(data []byte, err error) {
		if err != nil {
			logrus.Errorf("SubscribeEventLogs error:%v", err)
			return
		}
		processEventLogMsg(data, handler)
	}
	return c.csdk.SubscribeEvent(&sdkContext, string(sendData)), nil
}

func (c *Connection) UnsubscribeEventLogs(taskID string) {
	c.csdk.UnsubscribeEvent(taskID)
}

func (c *Connection) SubscribeBlockNumberNotify(handler func(int64)) error {
	var sdkContext csdk.CallbackChan
	c.blockNumberNotify = handler
	sdkContext.Handler = func(group string, blockNumber int64) {
		if group == c.csdk.GroupID() {
			c.notifyLock.Lock()
			if c.blockNumberNotify != nil {
				c.blockNumberNotify(int64(blockNumber))
			}
			c.notifyLock.Unlock()
		}
	}
	c.csdk.RegisterBlockNotifier(&sdkContext)
	return nil
}

func (c *Connection) UnsubscribeBlockNumberNotify() {
	c.notifyLock.Lock()
	defer c.notifyLock.Unlock()
	c.blockNumberNotify = nil
}

func (c *Connection) SubscribeAmopTopic(topic string, handler func(data []byte, response *[]byte)) error {
	var sdkContext csdk.CallbackChan
	sdkContext.Handler = func(peer, sqe string, data []byte) {
		var response []byte
		handler(data, &response)
		if len(response) > 0 {
			c.SendAmopResponse(peer, sqe, response)
		}
	}
	c.csdk.SubscribeAmopTopic(&sdkContext, topic)
	return nil
}

func (c *Connection) PublishAmopTopicMessage(ctx context.Context, topic string, data []byte, handler func([]byte, error)) error {
	op := &requestOp{respChanData: &csdk.CallbackChan{Data: make(chan csdk.Response, 1)}}
	c.csdk.PublishAmopTopicMsg(op.respChanData, topic, data, amopTimeout)
	go func() {
		select {
		case respBody := <-op.respChanData.Data:
			handler(respBody.Result.([]byte), nil)
		case <-ctx.Done():
			handler(nil, ctx.Err())
		}
	}()
	return nil
}

// Call performs a JSON-RPC call with the given arguments and unmarshals into
// result if no error occurred.
//
// The result must be a pointer so that package json can unmarshal into it. You
// can also pass nil, in which case the result is ignored.
func (c *Connection) Call(result interface{}, method string, args ...interface{}) error {
	ctx := context.Background()
	return c.CallContext(ctx, result, method, args...)
}

// CallContext performs a JSON-RPC call with the given arguments. If the context is
// canceled before the call has successfully returned, CallContext returns immediately.
//
// The result must be a pointer so that package json can unmarshal into it. You
// can also pass nil, in which case the result is ignored.
func (c *Connection) CallContext(ctx context.Context, result interface{}, method string, args ...interface{}) error {
	//logrus.Infof("CallContext method:%s\n", method)
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	op := &requestOp{respChanData: &csdk.CallbackChan{
		Data:             nil,
		MaxResponseBytes: csdk.DefaultMaxResponseBytes,
	}}

	switch method {
	case "asyncSendTransaction", "SendEncodedTransaction":
	default:
		op.respChanData.Data = make(chan csdk.Response, 1)
	}

	switch method {
	case "call":
		arg := args[0].(map[string]interface{})
		data := arg["data"].(string)
		to := arg["to"].(string)
		c.csdk.Call(op.respChanData, to, data)
	case "getGroupPeers":
		c.csdk.GetGroupPeers(op.respChanData)
	case "getPeers":
		c.csdk.GetPeers(op.respChanData)
	case "getBlockNumber":
		c.csdk.GetBlockNumber(op.respChanData)
	case "getBlockByNumber":
		blockNumber := args[0].(int64)
		onlyHeader := args[1].(bool)
		onlyTxHash := args[2].(bool)
		c.csdk.GetBlockByNumber(op.respChanData, blockNumber, onlyHeader, onlyTxHash)
	case "getBlockByHash":
		blockHash := args[0].(string)
		onlyHeader := args[1].(bool)
		onlyTxHash := args[2].(bool)
		c.csdk.GetBlockByHash(op.respChanData, blockHash, onlyHeader, onlyTxHash)
	case "getBlockHashByNumber":
		blockNumber := args[0].(int64)
		c.csdk.GetBlockHashByNumber(op.respChanData, blockNumber)
	case "getPbftView":
		c.csdk.GetPbftView(op.respChanData)
	case "getCode":
		address := args[0].(string)
		c.csdk.GetCode(op.respChanData, address)
	case "getSyncStatus":
		c.csdk.GetSyncStatus(op.respChanData)
	case "getConsensusStatus":
		c.csdk.GetConsensusStatus(op.respChanData)
	case "getSealerList":
		c.csdk.GetSealerList(op.respChanData)
	case "getObserverList":
		c.csdk.GetObserverList(op.respChanData)
	case "getTransactionReceipt":
		txHash := args[0].(string)
		withProof := args[1].(bool)
		c.csdk.GetTransactionReceipt(op.respChanData, txHash, withProof)
	case "getTransactionByHash":
		txHash := args[0].(string)
		withProof := args[1].(bool)
		c.csdk.GetTransaction(op.respChanData, txHash, withProof)
	case "getSystemConfigByKey":
		key := args[0].(string)
		c.csdk.GetSystemConfigByKey(op.respChanData, key)
	case "getTotalTransactionCount":
		c.csdk.GetTotalTransactionCount(op.respChanData)
	case "getNodeInfo":
		nodeID := args[0].(string)
		c.csdk.GetNodeInfo(op.respChanData, nodeID)
	case "getGroupList":
		c.csdk.GetGroupList(op.respChanData)
	case "getGroupInfo":
		c.csdk.GetGroupInfo(op.respChanData)
	case "getGroupInfoList":
		c.csdk.GetGroupInfoList(op.respChanData)
	case "getPendingTxSize":
		c.csdk.GetPendingTxSize(op.respChanData)
	case "asyncSendTransaction":
		data := hexutil.Encode(args[0].([]byte))
		contractAddress := args[1].(string)
		op.respChanData.Handler = wrapTransactionResponsesHandler(args[2].(func(*types.Receipt, error)))
		var abiStr string
		if len(args) >= 4 && len(contractAddress) == 0 {
			abiStr = args[3].(string)
		}
		_, err := c.csdk.CreateAndSendTransaction(op.respChanData, contractAddress, data, abiStr, "", false)
		if err != nil {
			return err
		}
	case "sendTransaction":
		data := hexutil.Encode(args[0].([]byte))
		contractAddress := args[1].(string)
		var abiStr string
		if len(args) >= 3 && len(contractAddress) == 0 {
			abiStr = args[2].(string)
		}
		_, err := c.csdk.CreateAndSendTransaction(op.respChanData, contractAddress, data, abiStr, "", false)
		if err != nil {
			return err
		}
	case "SendEncodedTransaction":
		encodedTransaction := args[0].([]byte)
		withProof := args[1].(bool)
		if len(args) >= 3 {
			op.respChanData.Handler = wrapTransactionResponsesHandler(args[2].(func(*types.Receipt, error)))
		} else {
			op.respChanData.Data = make(chan csdk.Response, 1)
		}
		err := c.csdk.SendEncodedTransaction(op.respChanData, encodedTransaction, withProof)
		if err != nil {
			return err
		}
	default:
		return ErrNoRpcMethod
	}
	// async send transaction
	if op.respChanData.Handler != nil {
		return nil
	} else {
		// dispatch has accepted the request and will close the channel when it quits.
		switch resp, _, err := op.waitRpcMessage(ctx); {
		case err != nil:
			return err
		case resp.Error != nil:
			return resp.Error
		case len(resp.Result) == 0:
			logrus.Errorf("result is null, %+v, err:%+v \n", resp, err)
			return ErrNoResult
		default:
			return json.Unmarshal(resp.Result, &result)
		}
	}
}

func (c *Connection) sendRPCRequest(group, node, jsonRequest string) (*jsonrpcMessage, error) {
	callback := &csdk.CallbackChan{Data: make(chan csdk.Response, 1)}
	err := c.csdk.SendRPCRequest(group, node, jsonRequest, callback)
	if err != nil {
		return nil, err
	}
	respBody := <-callback.Data
	var respData jsonrpcMessage
	if respBody.Err == nil {
		if err = json.Unmarshal(respBody.Result.([]byte), &respData); err != nil {
			return nil, err
		}
		return &respData, nil
	}
	return nil, respBody.Err
}
