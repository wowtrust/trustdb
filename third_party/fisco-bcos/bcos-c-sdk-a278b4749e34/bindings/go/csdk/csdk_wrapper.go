package csdk

// #cgo darwin,arm64 LDFLAGS: -L/usr/local/lib/ -lbcos-c-sdk-aarch64
// #cgo darwin,amd64 LDFLAGS: -L/usr/local/lib/ -lbcos-c-sdk
// #cgo linux,amd64 LDFLAGS: -L/usr/local/lib/ -lbcos-c-sdk
// #cgo linux,arm64 LDFLAGS: -L/usr/local/lib/ -lbcos-c-sdk-aarch64
// #cgo windows,amd64 LDFLAGS: -lbcos-c-sdk
// #cgo CFLAGS: -I./
// #include <stdint.h>
// #include "../../../bcos-c-sdk/bcos_sdk_c_common.h"
// #include "../../../bcos-c-sdk/bcos_sdk_c.h"
// #include "../../../bcos-c-sdk/bcos_sdk_c_error.h"
// #include "../../../bcos-c-sdk/bcos_sdk_c_rpc.h"
// #include "../../../bcos-c-sdk/bcos_sdk_c_uti_tx.h"
// #include "../../../bcos-c-sdk/bcos_sdk_c_amop.h"
// #include "../../../bcos-c-sdk/bcos_sdk_c_event_sub.h"
// #include "../../../bcos-c-sdk/bcos_sdk_c_uti_keypair.h"
// void on_recv_resp_callback(struct bcos_sdk_c_struct_response *);
// void on_recv_event_resp_callback(struct bcos_sdk_c_struct_response *);
// void on_recv_amop_publish_resp(struct bcos_sdk_c_struct_response *);
// void on_recv_amop_subscribe_resp(char*, char*, struct bcos_sdk_c_struct_response *);
// void on_recv_notify_resp_callback(char*, int64_t, void* );
// static size_t trustdb_bounded_strlen(const char* value, size_t limit)
// {
//     if (value == NULL) { return 0; }
//     size_t length = 0;
//     while (length < limit && value[length] != '\0') { ++length; }
//     return length;
// }
// static void* trustdb_context_from_token(uintptr_t token) { return (void*)token; }
// static uintptr_t trustdb_token_from_context(void* context) { return (uintptr_t)context; }
import "C"

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	cache "github.com/patrickmn/go-cache"
)

type CSDK struct {
	sdk             unsafe.Pointer
	smCrypto        bool
	wasm            bool
	chainID         *C.char
	groupID         *C.char
	keyPair         unsafe.Pointer
	privateKeyBytes []byte
	keyPairMutex    sync.Mutex
}

var contextCache = newContextCache()
var indexCache = cache.New(5*time.Minute, 10*time.Minute)
var contextSequence atomic.Uint64

const (
	// DefaultMaxResponseBytes is deliberately larger than TrustDB's largest
	// admitted decoded component (4 MiB contract code becomes about 8 MiB as
	// JSON hex), while still bounding allocation before C.GoBytes.
	DefaultMaxResponseBytes = (8 << 20) + 64
	DefaultMessageTimeoutMS = 15_000
	maxNativeErrorBytes     = 4 << 10
	maxNativeVersionBytes   = 4 << 10
	maxNativeIdentityBytes  = 4 << 10
	singleShotContextTTL    = time.Duration(DefaultMessageTimeoutMS+5_000) * time.Millisecond
)

const C_SDK_ECDSA_CRYPTO = C.int(0)
const C_SDK_SM_CRYPTO = C.int(1)

func newContextCache() *cache.Cache {
	items := cache.New(singleShotContextTTL, time.Second)
	items.OnEvicted(func(key string, value interface{}) {
		token, err := strconv.ParseUint(key, 10, 64)
		if err != nil {
			return
		}
		if callback, ok := value.(*CallbackChan); ok {
			callback.forgetContext(uintptr(token))
		}
	})
	return items
}

type AmopMessageContext struct {
	Peer string
	Seq  string
	Data []byte
}

type Response struct {
	Result interface{}
	Err    error
}

type CallbackChan struct {
	sdk     unsafe.Pointer
	Data    chan Response
	Handler interface{}
	// MaxResponseBytes is checked against the native size_t before any Go
	// allocation. Zero selects DefaultMaxResponseBytes.
	MaxResponseBytes int
	contextMu        sync.Mutex
	contextTokens    map[uintptr]struct{}
}

// Wait returns promptly when ctx is canceled. Data must be buffered so a late
// native callback can complete context-cache cleanup without blocking after
// the caller has returned.
func (c *CallbackChan) Wait(ctx context.Context) (Response, error) {
	if c == nil || c.Data == nil || cap(c.Data) == 0 {
		return Response{}, errors.New("FISCO BCOS callback channel must be buffered")
	}
	select {
	case response := <-c.Data:
		return response, nil
	case <-ctx.Done():
		c.releaseContexts()
		return Response{}, ctx.Err()
	}
}

// ValidateResponseSize is shared by the callback and conformance tests. The
// native size is unsigned; values above the configured cap (or a nonsensical
// cap) fail before converting to C.int for C.GoBytes.
func ValidateResponseSize(size uint64, maximum int) error {
	if maximum <= 0 {
		maximum = DefaultMaxResponseBytes
	}
	if maximum > int(^uint32(0)>>1) || size > uint64(maximum) {
		return fmt.Errorf("FISCO BCOS native response exceeds %d bytes", maximum)
	}
	return nil
}

//export on_recv_notify_resp_callback
func on_recv_notify_resp_callback(group *C.char, block C.int64_t, context unsafe.Pointer) {
	chanData := getContext(context, false)
	if chanData == nil {
		return
	}
	groupID, err := boundedCString(group, maxNativeIdentityBytes)
	if err != nil {
		return
	}
	chanData.Handler.(func(string, uint64))(groupID, uint64(block))
}

//export on_recv_amop_subscribe_resp
func on_recv_amop_subscribe_resp(endpoint *C.char, seq *C.char, resp *C.struct_bcos_sdk_c_struct_response) {
	if resp == nil {
		return
	}
	chanData := getContext(resp.context, false)
	if chanData == nil {
		return
	}
	data, err := copyNativeResponse(resp, chanData.MaxResponseBytes)
	if err != nil {
		return
	}
	peer, err := boundedCString(endpoint, maxNativeIdentityBytes)
	if err != nil {
		return
	}
	sequence, err := boundedCString(seq, maxNativeIdentityBytes)
	if err != nil {
		return
	}
	chanData.Handler.(func(string, string, []byte))(peer, sequence, data)
}

//export on_recv_amop_publish_resp
func on_recv_amop_publish_resp(resp *C.struct_bcos_sdk_c_struct_response) {
	on_callback_once(resp)
}

//export on_recv_resp_callback
func on_recv_resp_callback(resp *C.struct_bcos_sdk_c_struct_response) {
	on_callback_once(resp)
}

//export on_recv_event_resp_callback
func on_recv_event_resp_callback(resp *C.struct_bcos_sdk_c_struct_response) {
	if resp == nil {
		return
	}
	chanData := getContext(resp.context, false)
	if chanData == nil {
		return
	}
	data, err := copyNativeResponse(resp, chanData.MaxResponseBytes)
	chanData.Handler.(func([]byte, error))(data, err)
}

func on_callback_once(resp *C.struct_bcos_sdk_c_struct_response) {
	if resp == nil {
		return
	}
	chanData := getContext(resp.context, true)
	if chanData == nil {
		return
	}
	data, err := copyNativeResponse(resp, chanData.MaxResponseBytes)
	respData := Response{Result: data, Err: err}
	if chanData.Data != nil {
		select {
		case chanData.Data <- respData:
		default:
			// A callback is single-shot. A full buffered channel means the
			// consumer has already returned or received a response.
		}
	} else {
		go chanData.Handler.(func([]byte, error))(respData.Result.([]byte), respData.Err)
	}
}

func copyNativeResponse(resp *C.struct_bcos_sdk_c_struct_response, maximum int) ([]byte, error) {
	if resp == nil {
		return nil, errors.New("FISCO BCOS native response is nil")
	}
	if int(resp.error) != 0 {
		description, err := boundedCString(resp.desc, maxNativeErrorBytes)
		if err != nil {
			description = "native error description exceeded the safety limit"
		}
		return []byte{}, fmt.Errorf(
			"something is wrong, error: %d, errorMessage: %s",
			resp.error,
			description,
		)
	}
	size := uint64(resp.size)
	if err := ValidateResponseSize(size, maximum); err != nil {
		return []byte{}, err
	}
	if size != 0 && resp.data == nil {
		return []byte{}, errors.New("FISCO BCOS native response has nil data")
	}
	return C.GoBytes(unsafe.Pointer(resp.data), C.int(size)), nil
}

func boundedCString(value *C.char, limit int) (string, error) {
	if value == nil || limit <= 0 {
		return "", errors.New("native string is empty or has an invalid limit")
	}
	length := uint64(C.trustdb_bounded_strlen(value, C.size_t(limit+1)))
	if length > uint64(limit) {
		return "", fmt.Errorf("native string exceeds %d bytes", limit)
	}
	return C.GoStringN(value, C.int(length)), nil
}

// Version returns the version reported by the loaded native shared library.
func Version() (string, error) {
	value := C.bcos_sdk_version()
	if value == nil {
		return "", errors.New("FISCO BCOS native SDK returned an empty version")
	}
	defer C.bcos_sdk_c_free(unsafe.Pointer(value))
	return boundedCString(value, maxNativeVersionBytes)
}

func setContext(callback *CallbackChan) unsafe.Pointer {
	return registerContext(callback, singleShotContextTTL)
}

func setPersistentContext(callback *CallbackChan) unsafe.Pointer {
	return registerContext(callback, cache.NoExpiration)
}

func registerContext(callback *CallbackChan, lifetime time.Duration) unsafe.Pointer {
	if callback == nil {
		return nil
	}
	token := uintptr(contextSequence.Add(1))
	if token == 0 {
		token = uintptr(contextSequence.Add(1))
	}
	key := contextKey(token)
	callback.contextMu.Lock()
	if callback.contextTokens == nil {
		callback.contextTokens = make(map[uintptr]struct{})
	}
	callback.contextTokens[token] = struct{}{}
	callback.contextMu.Unlock()
	contextCache.Set(key, callback, lifetime)
	// The C SDK treats context as an opaque value and returns it unchanged.
	// A monotonic token avoids both C allocation ownership and late-callback
	// use-after-free/ABA hazards.
	return C.trustdb_context_from_token(C.uintptr_t(token))
}

func getContext(index unsafe.Pointer, delete bool) *CallbackChan {
	token := uintptr(C.trustdb_token_from_context(index))
	if token == 0 {
		return nil
	}
	context, found := contextCache.Get(contextKey(token))
	if !found {
		return nil
	}
	callback, ok := context.(*CallbackChan)
	if !ok {
		return nil
	}
	if delete {
		contextCache.Delete(contextKey(token))
		callback.forgetContext(token)
	}
	return callback
}

func releaseContext(index unsafe.Pointer) {
	token := uintptr(C.trustdb_token_from_context(index))
	if token == 0 {
		return
	}
	context, found := contextCache.Get(contextKey(token))
	contextCache.Delete(contextKey(token))
	if callback, ok := context.(*CallbackChan); found && ok {
		callback.forgetContext(token)
	}
}

func (c *CallbackChan) releaseContexts() {
	if c == nil {
		return
	}
	c.contextMu.Lock()
	tokens := make([]uintptr, 0, len(c.contextTokens))
	for token := range c.contextTokens {
		tokens = append(tokens, token)
	}
	clear(c.contextTokens)
	c.contextMu.Unlock()
	for _, token := range tokens {
		contextCache.Delete(contextKey(token))
	}
}

func (c *CallbackChan) forgetContext(token uintptr) {
	c.contextMu.Lock()
	delete(c.contextTokens, token)
	c.contextMu.Unlock()
}

func contextKey(token uintptr) string {
	return strconv.FormatUint(uint64(token), 10)
}

func NewSDK(groupID string, host string, port int, isSmSsl bool, privateKey []byte, disableSsl bool, tlsCaPath, tlsKeyPath, tlsCertPath, tlsSmEnKey, tlsSEnCert string) (*CSDK, error) {
	cHost := C.CString(host)
	cPort := C.int(port)
	cIsSmSsl := C.int(0)
	if isSmSsl {
		cIsSmSsl = C.int(1)
	}
	config := C.bcos_sdk_create_config(cIsSmSsl, cHost, cPort)
	defer C.bcos_sdk_c_config_destroy(unsafe.Pointer(config))

	cTlsCaPath := C.CString(tlsCaPath)
	cTlsKeyPath := C.CString(tlsKeyPath)
	cTlsCertPath := C.CString(tlsCertPath)
	if !disableSsl {
		if isSmSsl {
			C.bcos_sdk_c_free(unsafe.Pointer(config.sm_cert_config.ca_cert))
			config.sm_cert_config.ca_cert = cTlsCaPath
			C.bcos_sdk_c_free(unsafe.Pointer(config.sm_cert_config.node_key))
			config.sm_cert_config.node_key = cTlsKeyPath
			C.bcos_sdk_c_free(unsafe.Pointer(config.sm_cert_config.node_cert))
			config.sm_cert_config.node_cert = cTlsCertPath

			C.bcos_sdk_c_free(unsafe.Pointer(config.sm_cert_config.en_node_key))
			cTlsSmEnKey := C.CString(tlsSmEnKey)
			config.sm_cert_config.en_node_key = cTlsSmEnKey
			C.bcos_sdk_c_free(unsafe.Pointer(config.sm_cert_config.en_node_cert))
			cTlsSmEnCert := C.CString(tlsSEnCert)
			config.sm_cert_config.en_node_cert = cTlsSmEnCert
		} else {
			C.bcos_sdk_c_free(unsafe.Pointer(config.cert_config.ca_cert))
			config.cert_config.ca_cert = cTlsCaPath
			C.bcos_sdk_c_free(unsafe.Pointer(config.cert_config.node_key))
			config.cert_config.node_key = cTlsKeyPath
			C.bcos_sdk_c_free(unsafe.Pointer(config.cert_config.node_cert))
			config.cert_config.node_cert = cTlsCertPath
		}
	} else {
		config.disable_ssl = C.int(1)
	}
	// A finite native timeout guarantees that canceled Go calls eventually
	// receive a terminal callback and release their callback-cache entry.
	config.message_timeout_ms = C.int(DefaultMessageTimeoutMS)
	sdk := C.bcos_sdk_create(config)
	if sdk == nil {
		message := C.bcos_sdk_get_last_error_msg()
		//defer C.free(unsafe.Pointer(message))
		return nil, fmt.Errorf("bcos_sdk_create failed with error: %s", C.GoString(message))
	}
	C.bcos_sdk_start(sdk)
	if C.bcos_sdk_get_last_error() != 0 {
		message := C.bcos_sdk_get_last_error_msg()
		//defer C.free(unsafe.Pointer(message))
		return nil, fmt.Errorf("bcos_sdk_start failed with error: %s", C.GoString(message))
	}

	var wasm, smCrypto C.int
	group := C.CString(groupID)
	C.bcos_sdk_get_group_wasm_and_crypto(sdk, group, &wasm, &smCrypto)
	keyPair := C.bcos_sdk_create_keypair_by_private_key(smCrypto, unsafe.Pointer(&privateKey[0]), C.uint(len(privateKey)))
	if keyPair == nil {
		message := C.bcos_sdk_get_last_error_msg()
		C.bcos_sdk_c_free(unsafe.Pointer(group))
		return nil, fmt.Errorf("bcos_sdk_create_keypair_by_private_key failed with error: %s", C.GoString(message))
	}
	chainID := C.bcos_sdk_get_group_chain_id(sdk, group)
	return &CSDK{
		sdk:             sdk,
		smCrypto:        smCrypto != 0,
		wasm:            wasm != 0,
		groupID:         group,
		chainID:         chainID,
		privateKeyBytes: privateKey,
		keyPair:         keyPair,
	}, nil
}

func NewSDKByConfigFile(configFile string, groupID string, privateKey []byte) (*CSDK, error) {
	config := C.CString(configFile)
	defer C.free(unsafe.Pointer(config))
	sdk := C.bcos_sdk_create_by_config_file(config)
	if sdk == nil {
		message := C.bcos_sdk_get_last_error_msg()
		//defer C.free(unsafe.Pointer(message))
		return nil, fmt.Errorf("bcos sdk create by config file failed with error: %s", C.GoString(message))
	}

	C.bcos_sdk_start(sdk)
	if C.bcos_sdk_get_last_error() != 0 {
		message := C.bcos_sdk_get_last_error_msg()
		//defer C.free(unsafe.Pointer(message))
		return nil, fmt.Errorf("bcos sdk start failed with error: %s", C.GoString(message))
	}

	var wasm, smCrypto C.int
	CGroupID := C.CString(groupID)
	C.bcos_sdk_get_group_wasm_and_crypto(sdk, CGroupID, &wasm, &smCrypto)
	keyPair := C.bcos_sdk_create_keypair_by_private_key(smCrypto, unsafe.Pointer(&privateKey[0]), C.uint(len(privateKey)))
	if keyPair == nil {
		message := C.bcos_sdk_get_last_error_msg()
		C.bcos_sdk_c_free(unsafe.Pointer(CGroupID))
		return nil, fmt.Errorf("bcos_sdk_create_keypair_by_private_key failed with error: %s", C.GoString(message))
	}
	chainID := C.bcos_sdk_get_group_chain_id(sdk, CGroupID)
	return &CSDK{
		sdk:             sdk,
		smCrypto:        smCrypto != 0,
		wasm:            wasm != 0,
		groupID:         CGroupID,
		chainID:         chainID,
		privateKeyBytes: privateKey,
		keyPair:         keyPair,
	}, nil
}

func (csdk *CSDK) Close() {
	csdk.keyPairMutex.Lock()
	defer csdk.keyPairMutex.Unlock()
	C.bcos_sdk_stop(csdk.sdk)
	C.bcos_sdk_destroy(csdk.sdk)
	C.bcos_sdk_c_free(unsafe.Pointer(csdk.groupID))
	C.bcos_sdk_c_free(unsafe.Pointer(csdk.chainID))
	C.bcos_sdk_destroy_keypair(csdk.keyPair)
}

func (csdk *CSDK) GroupID() string {
	return C.GoString(csdk.groupID)
}

func (csdk *CSDK) ChainID() string {
	return C.GoString(csdk.chainID)
}

func (csdk *CSDK) PrivateKeyBytes() []byte {
	return csdk.privateKeyBytes
}

// SetPrivateKey set private key
func (csdk *CSDK) SetPrivateKey(privateKeyBytes []byte) error {
	cryptoType := C_SDK_ECDSA_CRYPTO
	if csdk.smCrypto {
		cryptoType = C_SDK_SM_CRYPTO
	}
	keyPair := C.bcos_sdk_create_keypair_by_private_key(cryptoType, unsafe.Pointer(&privateKeyBytes[0]), C.uint(len(privateKeyBytes)))
	if keyPair == nil {
		message := C.bcos_sdk_get_last_error_msg()
		return fmt.Errorf("SetPrivateKey bcos_sdk_create_keypair_by_private_key failed with error: %s", C.GoString(message))
	}
	csdk.keyPairMutex.Lock()
	defer csdk.keyPairMutex.Unlock()
	C.bcos_sdk_destroy_keypair(csdk.keyPair)
	csdk.keyPair = keyPair
	return nil
}

func (csdk *CSDK) SMCrypto() bool {
	return csdk.smCrypto
}

func (csdk *CSDK) WASM() bool {
	return csdk.wasm
}

func (csdk *CSDK) Call(chanData *CallbackChan, to string, data string) {
	cData := C.CString(data)
	cTo := C.CString(to)
	defer C.free(unsafe.Pointer(cData))
	defer C.free(unsafe.Pointer(cTo))
	C.bcos_rpc_call(csdk.sdk, csdk.groupID, nil, cTo, cData, C.bcos_sdk_c_struct_response_cb(C.on_recv_resp_callback), setContext(chanData))
}

func (csdk *CSDK) GetTransaction(chanData *CallbackChan, txHash string, withProof bool) {
	cTxhash := C.CString(txHash)
	cProof := C.int(0)
	if withProof {
		cProof = C.int(1)
	}
	defer C.free(unsafe.Pointer(cTxhash))
	C.bcos_rpc_get_transaction(csdk.sdk, csdk.groupID, nil, cTxhash, cProof, C.bcos_sdk_c_struct_response_cb(C.on_recv_resp_callback), setContext(chanData))
}

func (csdk *CSDK) GetTransactionReceipt(chanData *CallbackChan, txHash string, withProof bool) {
	cTxhash := C.CString(txHash)
	cProof := C.int(0)
	if withProof {
		cProof = C.int(1)
	}
	defer C.free(unsafe.Pointer(cTxhash))
	C.bcos_rpc_get_transaction_receipt(csdk.sdk, csdk.groupID, nil, cTxhash, cProof, C.bcos_sdk_c_struct_response_cb(C.on_recv_resp_callback), setContext(chanData))
}

func (csdk *CSDK) GetBlockLimit() int {
	return int(C.bcos_rpc_get_block_limit(csdk.sdk, csdk.groupID))
}

func (csdk *CSDK) GetCode(chanData *CallbackChan, address string) {
	cAddress := C.CString(address)
	defer C.free(unsafe.Pointer(cAddress))
	C.bcos_rpc_get_code(csdk.sdk, csdk.groupID, nil, cAddress, C.bcos_sdk_c_struct_response_cb(C.on_recv_resp_callback), setContext(chanData))
}

func (csdk *CSDK) GetSealerList(chanData *CallbackChan) {
	C.bcos_rpc_get_sealer_list(csdk.sdk, csdk.groupID, nil, C.bcos_sdk_c_struct_response_cb(C.on_recv_resp_callback), setContext(chanData))
}

func (csdk *CSDK) GetObserverList(chanData *CallbackChan) {
	C.bcos_rpc_get_observer_list(csdk.sdk, csdk.groupID, nil, C.bcos_sdk_c_struct_response_cb(C.on_recv_resp_callback), setContext(chanData))
}

func (csdk *CSDK) GetPbftView(chanData *CallbackChan) {
	C.bcos_rpc_get_pbft_view(csdk.sdk, csdk.groupID, nil, C.bcos_sdk_c_struct_response_cb(C.on_recv_resp_callback), setContext(chanData))
}

func (csdk *CSDK) GetPendingTxSize(chanData *CallbackChan) {
	C.bcos_rpc_get_pending_tx_size(csdk.sdk, csdk.groupID, nil, C.bcos_sdk_c_struct_response_cb(C.on_recv_resp_callback), setContext(chanData))
}

func (csdk *CSDK) GetSyncStatus(chanData *CallbackChan) {
	C.bcos_rpc_get_sync_status(csdk.sdk, csdk.groupID, nil, C.bcos_sdk_c_struct_response_cb(C.on_recv_resp_callback), setContext(chanData))
}

func (csdk *CSDK) GetConsensusStatus(chanData *CallbackChan) {
	C.bcos_rpc_get_consensus_status(csdk.sdk, csdk.groupID, nil, C.bcos_sdk_c_struct_response_cb(C.on_recv_resp_callback), setContext(chanData))
}

func (csdk *CSDK) GetGroupPeers(chanData *CallbackChan) {
	C.bcos_rpc_get_group_peers(csdk.sdk, csdk.groupID, C.bcos_sdk_c_struct_response_cb(C.on_recv_resp_callback), setContext(chanData))
}

func (csdk *CSDK) GetPeers(chanData *CallbackChan) {
	C.bcos_rpc_get_peers(csdk.sdk, C.bcos_sdk_c_struct_response_cb(C.on_recv_resp_callback), setContext(chanData))
}

func (csdk *CSDK) GetBlockNumber(chanData *CallbackChan) {
	C.bcos_rpc_get_block_number(csdk.sdk, csdk.groupID, nil, C.bcos_sdk_c_struct_response_cb(C.on_recv_resp_callback), setContext(chanData))
}

func (csdk *CSDK) GetBlockHashByNumber(chanData *CallbackChan, blockNumber int64) {
	cBlockNumber := C.int64_t(blockNumber)
	C.bcos_rpc_get_block_hash_by_number(csdk.sdk, csdk.groupID, nil, cBlockNumber, C.bcos_sdk_c_struct_response_cb(C.on_recv_resp_callback), setContext(chanData))
}

func (csdk *CSDK) GetBlockByHash(chanData *CallbackChan, blockHash string, onlyHeader, onlyTxHash bool) {
	cBlockHash := C.CString(blockHash)
	cOnlyHeader := C.int(0)
	if onlyHeader {
		cOnlyHeader = C.int(1)
	}
	cOnlyTxHash := C.int(0)
	if onlyTxHash {
		cOnlyTxHash = C.int(1)
	}
	defer C.free(unsafe.Pointer(cBlockHash))
	C.bcos_rpc_get_block_by_hash(csdk.sdk, csdk.groupID, nil, cBlockHash, cOnlyHeader, cOnlyTxHash, C.bcos_sdk_c_struct_response_cb(C.on_recv_resp_callback), setContext(chanData))
}

func (csdk *CSDK) GetBlockByNumber(chanData *CallbackChan, blockNumber int64, onlyHeader, onlyTxHash bool) {
	cBlockNumber := C.int64_t(blockNumber)
	cOnlyHeader := C.int(0)
	if onlyHeader {
		cOnlyHeader = C.int(1)
	}
	cOnlyTxHash := C.int(0)
	if onlyTxHash {
		cOnlyTxHash = C.int(1)
	}
	C.bcos_rpc_get_block_by_number(csdk.sdk, csdk.groupID, nil, cBlockNumber, cOnlyHeader, cOnlyTxHash, C.bcos_sdk_c_struct_response_cb(C.on_recv_resp_callback), setContext(chanData))
}

func (csdk *CSDK) GetGroupList(chanData *CallbackChan) {
	C.bcos_rpc_get_group_list(csdk.sdk, C.bcos_sdk_c_struct_response_cb(C.on_recv_resp_callback), setContext(chanData))
}

func (csdk *CSDK) GetGroupInfo(chanData *CallbackChan) {
	C.bcos_rpc_get_group_info(csdk.sdk, csdk.groupID, C.bcos_sdk_c_struct_response_cb(C.on_recv_resp_callback), setContext(chanData))
}

func (csdk *CSDK) GetNodeInfo(chanData *CallbackChan, nodeID string) {
	cNodeID := C.CString(nodeID)
	defer C.free(unsafe.Pointer(cNodeID))
	C.bcos_rpc_get_group_node_info(csdk.sdk, csdk.groupID, cNodeID, C.bcos_sdk_c_struct_response_cb(C.on_recv_resp_callback), setContext(chanData))
}

func (csdk *CSDK) GetGroupInfoList(chanData *CallbackChan) {
	C.bcos_rpc_get_group_info_list(csdk.sdk, C.bcos_sdk_c_struct_response_cb(C.on_recv_resp_callback), setContext(chanData))
}

func (csdk *CSDK) GetTotalTransactionCount(chanData *CallbackChan) {
	C.bcos_rpc_get_total_transaction_count(csdk.sdk, csdk.groupID, nil, C.bcos_sdk_c_struct_response_cb(C.on_recv_resp_callback), setContext(chanData))
}

func (csdk *CSDK) GetSystemConfigByKey(chanData *CallbackChan, key string) {
	cKey := C.CString(key)
	defer C.free(unsafe.Pointer(cKey))
	C.bcos_rpc_get_system_config_by_key(csdk.sdk, csdk.groupID, nil, cKey, C.bcos_sdk_c_struct_response_cb(C.on_recv_resp_callback), setContext(chanData))
}

// SendRPCRequest to specific group or node, group and node can be empty
func (csdk *CSDK) SendRPCRequest(group, node, request string, chanData *CallbackChan) error {
	cGroup := C.CString(group)
	defer C.free(unsafe.Pointer(cGroup))
	cNode := C.CString(node)
	defer C.free(unsafe.Pointer(cNode))
	cRequest := C.CString(request)
	defer C.free(unsafe.Pointer(cRequest))
	index := setContext(chanData)
	C.bcos_rpc_generic_method_call_to_group_node(csdk.sdk, cGroup, cNode, cRequest, C.bcos_sdk_c_struct_response_cb(C.on_recv_resp_callback), index)
	if C.bcos_sdk_is_last_opr_success() == 0 {
		releaseContext(index)
		return fmt.Errorf("SendRPCRequest, error: %s", C.GoString(C.bcos_sdk_get_last_error_msg()))
	}
	return nil
}

// // amop
// func (csdk *CSDK) SubscribeAmopTopicDefaultHandler(topic []string) {
// 	cTopic := C.CString(topic)
// 	defer C.free(unsafe.Pointer(cTopic))
// 	cLen := C.size_t(len(topic))
// 	C.bcos_amop_subscribe_topic(csdk.sdk, &cTopic, cLen)
// }

func (csdk *CSDK) SubscribeAmopTopic(chanData *CallbackChan, topic string) {
	cTopic := C.CString(topic)
	defer C.free(unsafe.Pointer(cTopic))
	chanData.sdk = csdk.sdk
	index := setPersistentContext(chanData)
	indexCache.Set(topic, index, cache.NoExpiration)
	C.bcos_amop_subscribe_topic_with_cb(csdk.sdk, cTopic, C.bcos_sdk_c_struct_response_cb(C.on_recv_amop_subscribe_resp), index)
}

func (csdk *CSDK) UnsubscribeAmopTopic(topic string) {
	cTopic := C.CString(topic)
	defer C.free(unsafe.Pointer(cTopic))
	cLen := C.size_t(len(topic))
	C.bcos_amop_unsubscribe_topic(csdk.sdk, &cTopic, cLen)
	index, found := indexCache.Get(topic)
	if found {
		getContext(index.(unsafe.Pointer), true)
	}
}

func (csdk *CSDK) SendAmopResponse(peer, seq string, data []byte) {
	cPeer := C.CString(peer)
	cSeq := C.CString(seq)
	cData := C.CBytes(data)
	cLen := C.size_t(len(data))
	defer C.free(unsafe.Pointer(cPeer))
	defer C.free(unsafe.Pointer(cSeq))
	defer C.free(unsafe.Pointer(cData))
	C.bcos_amop_send_response(csdk.sdk, cPeer, cSeq, cData, cLen)
}

func (csdk *CSDK) PublishAmopTopicMsg(chanData *CallbackChan, topic string, data []byte, timeout int) {
	cTopic := C.CString(topic)
	cData := C.CBytes(data)
	cLen := C.size_t(len(data))
	cTimeout := C.uint32_t(timeout)
	defer C.free(unsafe.Pointer(cTopic))
	defer C.free(unsafe.Pointer(cData))
	C.bcos_amop_publish(csdk.sdk, cTopic, cData, cLen, cTimeout, C.bcos_sdk_c_struct_response_cb(C.on_recv_amop_publish_resp), setContext(chanData))
}

func (csdk *CSDK) BroadcastAmopMsg(topic string, data []byte) {
	cTopic := C.CString(topic)
	cData := C.CBytes(data)
	cLen := C.size_t(len(data))
	defer C.free(unsafe.Pointer(cTopic))
	defer C.free(unsafe.Pointer(cData))
	C.bcos_amop_broadcast(csdk.sdk, cTopic, cData, cLen)
}

// event
func (csdk *CSDK) SubscribeEvent(chanData *CallbackChan, params string) string {
	cParams := C.CString(params)
	defer C.free(unsafe.Pointer(cParams))
	chanData.sdk = csdk.sdk
	index := setPersistentContext(chanData)
	taskID := C.GoString(C.bcos_event_sub_subscribe_event(csdk.sdk, csdk.groupID, cParams, C.bcos_sdk_c_struct_response_cb(C.on_recv_event_resp_callback), index))
	indexCache.Set(taskID, index, cache.NoExpiration)
	return taskID
}

func (csdk *CSDK) UnsubscribeEvent(taskId string) { // TODO: CallbackChan task from contextCache
	cTaskId := C.CString(taskId)
	defer C.free(unsafe.Pointer(cTaskId))
	C.bcos_event_sub_unsubscribe_event(csdk.sdk, cTaskId)
	index, found := indexCache.Get(taskId)
	if found {
		getContext(index.(unsafe.Pointer), true)
	}
}

func (csdk *CSDK) RegisterBlockNotifier(chanData *CallbackChan) { // TODO: implement UnRegisterBlockNotifier
	C.bcos_sdk_register_block_notifier(csdk.sdk, csdk.groupID, setPersistentContext(chanData), C.bcos_sdk_c_struct_response_cb(C.on_recv_notify_resp_callback))
}

func (csdk *CSDK) CreateAndSendTransaction(chanData *CallbackChan, to string, data, abi, extraData string, withProof bool) ([]byte, error) {
	cTo := C.CString(to)
	defer C.free(unsafe.Pointer(cTo))
	cProof := C.int(0)
	if withProof {
		cProof = C.int(1)
	}
	cData := C.CString(data)
	defer C.free(unsafe.Pointer(cData))
	cAbi := C.CString(abi)
	defer C.free(unsafe.Pointer(cAbi))
	cExtraData := C.CString(extraData)
	defer C.free(unsafe.Pointer(cExtraData))
	var tx_hash *C.char
	var signed_tx *C.char
	block_limit := C.bcos_rpc_get_block_limit(csdk.sdk, csdk.groupID)
	if block_limit < 0 {
		return nil, fmt.Errorf("group not exist, group: %s", C.GoString(csdk.groupID))
	}
	csdk.keyPairMutex.Lock()
	C.bcos_sdk_create_signed_transaction_ver_extra_data(csdk.keyPair, csdk.groupID, csdk.chainID, cTo, cData, cAbi, block_limit, 0, cExtraData, &tx_hash, &signed_tx)
	if C.bcos_sdk_is_last_opr_success() == 0 {
		csdk.keyPairMutex.Unlock()
		return nil, fmt.Errorf("bcos_sdk_create_signed_transaction, error: %s", C.GoString(C.bcos_sdk_get_last_error_msg()))
	}
	csdk.keyPairMutex.Unlock()
	defer C.bcos_sdk_c_free(unsafe.Pointer(tx_hash))
	defer C.bcos_sdk_c_free(unsafe.Pointer(signed_tx))
	txHash, err := hex.DecodeString(strings.TrimPrefix(C.GoString(tx_hash), "0x"))
	if err != nil {
		return nil, err
	}
	index := setContext(chanData)
	C.bcos_rpc_send_transaction(csdk.sdk, csdk.groupID, nil, signed_tx, cProof, C.bcos_sdk_c_struct_response_cb(C.on_recv_resp_callback), index)

	if C.bcos_sdk_is_last_opr_success() == 0 {
		releaseContext(index)
		return txHash, fmt.Errorf("bcos rpc send transaction failed, error: %s", C.GoString(C.bcos_sdk_get_last_error_msg()))
	}
	return txHash, nil
}

func (csdk *CSDK) CreateEncodedTransactionDataV1(blockLimit int64, to string, input []byte, abi string) ([]byte, []byte, error) {
	cTo := C.CString(to)
	cInput := C.CString(string(input))
	cAbi := C.CString(abi)
	defer C.free(unsafe.Pointer(cTo))
	defer C.free(unsafe.Pointer(cInput))
	defer C.free(unsafe.Pointer(cAbi))
	inputHex := hex.EncodeToString(input)
	cInputHex := C.CString(inputHex)
	defer C.free(unsafe.Pointer(cInputHex))
	encodedTransactionPointer := C.bcos_sdk_create_transaction_data(csdk.groupID, csdk.chainID, cTo, cInputHex, cAbi, C.int64_t(blockLimit))
	defer C.bcos_sdk_destroy_transaction_data(encodedTransactionPointer)
	if C.bcos_sdk_is_last_opr_success() == 0 {
		return nil, nil, fmt.Errorf("bcos_sdk_create_transaction_data error: %s", C.GoString(C.bcos_sdk_get_last_error_msg()))
	}
	encodedTransactionData := C.bcos_sdk_encode_transaction_data(encodedTransactionPointer)
	defer C.bcos_sdk_c_free(unsafe.Pointer(encodedTransactionData))
	if C.bcos_sdk_is_last_opr_success() == 0 {
		return nil, nil, fmt.Errorf("bcos_sdk_create_transaction_data encode error: %s", C.GoString(C.bcos_sdk_get_last_error_msg()))
	}
	data, err := hex.DecodeString(strings.TrimPrefix(C.GoString(encodedTransactionData), "0x"))
	if err != nil {
		return nil, nil, err
	}
	cryptoType := C.int(0)
	if csdk.smCrypto {
		cryptoType = C.int(1)
	}
	dataHashHex := C.bcos_sdk_calc_transaction_data_hash(cryptoType, encodedTransactionPointer)
	defer C.bcos_sdk_c_free(unsafe.Pointer(dataHashHex))
	dataHash, err := hex.DecodeString(strings.TrimPrefix(C.GoString(dataHashHex), "0x"))
	if err != nil {
		return nil, nil, err
	}
	if C.bcos_sdk_is_last_opr_success() == 0 {
		return nil, nil, fmt.Errorf("bcos_sdk_create_transaction_data hash error: %s", C.GoString(C.bcos_sdk_get_last_error_msg()))
	}
	return data, dataHash, nil
}

func (csdk *CSDK) CreateEncodedSignature(hash []byte) ([]byte, error) {
	hexHash := hex.EncodeToString(hash)
	cHexHash := C.CString(hexHash)
	csdk.keyPairMutex.Lock()
	defer csdk.keyPairMutex.Unlock()
	signatureHex := C.bcos_sdk_sign_transaction_data_hash(csdk.keyPair, cHexHash)
	defer C.bcos_sdk_c_free(unsafe.Pointer(signatureHex))
	if C.bcos_sdk_is_last_opr_success() == 0 {
		return nil, fmt.Errorf("bcos_sdk_sign_transaction_data_hash error: %s", C.GoString(C.bcos_sdk_get_last_error_msg()))
	}
	signatureBytes, err := hex.DecodeString(strings.TrimPrefix(C.GoString(signatureHex), "0x"))
	if err != nil {
		return nil, err
	}
	return signatureBytes, nil
}

func (csdk *CSDK) CreateEncodedTransaction(transactionData, dataHash, signature []byte, attribute int32, extraData string) ([]byte, error) {
	cExtraData := C.CString("")
	if len(extraData) != 0 {
		cExtraData := C.CString(extraData)
		defer C.free(unsafe.Pointer(cExtraData))
	}
	cDataHash := C.CString(hex.EncodeToString(dataHash))
	defer C.free(unsafe.Pointer(cDataHash))
	cSignature := C.CString(hex.EncodeToString(signature))
	defer C.free(unsafe.Pointer(cSignature))
	cTransactionData := C.CString(hex.EncodeToString(transactionData))
	defer C.free(unsafe.Pointer(cTransactionData))
	cJson := C.bcos_sdk_decode_transaction_data(cTransactionData)
	defer C.bcos_sdk_c_free(unsafe.Pointer(cJson))
	txDataPointer := C.bcos_sdk_create_transaction_data_with_json(cJson)
	defer C.bcos_sdk_destroy_transaction_data(txDataPointer)
	encodedTransactionHex := C.bcos_sdk_create_signed_transaction_with_signed_data_ver_extra_data(txDataPointer, cSignature, cDataHash, C.int(attribute), cExtraData)
	if C.bcos_sdk_is_last_opr_success() == 0 {
		return nil, fmt.Errorf("bcos_sdk_create_transaction_data_from_tx_data error: %s", C.GoString(C.bcos_sdk_get_last_error_msg()))
	}
	data, err := hex.DecodeString(strings.TrimPrefix(C.GoString(encodedTransactionHex), "0x"))
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (csdk *CSDK) SendEncodedTransaction(chanData *CallbackChan, encodedTransaction []byte, withProof bool) error {
	cEncodedTransaction := C.CString(hex.EncodeToString(encodedTransaction))
	defer C.free(unsafe.Pointer(cEncodedTransaction))
	cProof := C.int(0)
	if withProof {
		cProof = C.int(1)
	}
	index := setContext(chanData)
	C.bcos_rpc_send_transaction(csdk.sdk, csdk.groupID, nil, cEncodedTransaction, cProof, C.bcos_sdk_c_struct_response_cb(C.on_recv_resp_callback), index)
	if C.bcos_sdk_is_last_opr_success() == 0 {
		releaseContext(index)
		return fmt.Errorf("bcos_rpc_send_raw_transaction error: %s", C.GoString(C.bcos_sdk_get_last_error_msg()))
	}
	return nil
}
