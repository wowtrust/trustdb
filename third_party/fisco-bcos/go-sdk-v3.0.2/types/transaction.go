package types

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"github.com/FISCO-BCOS/go-sdk/v3/smcrypto/sm3"
	"github.com/TarsCloud/TarsGo/tars/protocol/codec"
	"github.com/ethereum/go-ethereum/common"
	"golang.org/x/crypto/sha3"
)

var (
	ErrInvalidSig = errors.New("invalid raw transaction v, r, s values")
)

type TransactionData struct {
	Version              int32           `json:"version" tars:"version,tag:1,require:false"`
	ChainID              string          `json:"chainID" tars:"chainID,tag:2,require:false"`
	GroupID              string          `json:"groupID" tars:"groupID,tag:3,require:false"`
	BlockLimit           int64           `json:"blockLimit" tars:"blockLimit,tag:4,require:false"`
	Nonce                string          `json:"nonce" tars:"nonce,tag:5,require:false"`
	To                   *common.Address `json:"to" tars:"to,tag:6,require:false"`
	Input                []byte          `json:"input" tars:"input,tag:7,require:false"`
	Abi                  string          `json:"abi" tars:"abi,tag:8,require:false"`
	Value                *big.Int        `json:"value" tars:"value,tag:9,require:false"`
	GasPrice             *big.Int        `json:"gasPrice" tars:"gasPrice,tag:10,require:false"`
	GasLimit             int64           `json:"gasLimit" tars:"gasLimit,tag:11,require:false"`
	MaxFeePerGas         *big.Int        `json:"maxFeePerGas" tars:"maxFeePerGas,tag:12,require:false"`
	MaxPriorityFeePerGas *big.Int        `json:"maxPriorityFeePerGas" tars:"maxPriorityFeePerGas,tag:13,require:false"`
}

func (st *TransactionData) ResetDefault() {
}

func (st *TransactionData) Bytes() []byte {
	buf := codec.NewBuffer()
	st.WriteTo(buf)
	return buf.ToBytes()
}

func readBigIntFromHex(readBuf *codec.Reader, tag byte, require bool) (*big.Int, error) {
	var hexStr string
	err := readBuf.ReadString(&hexStr, tag, require)
	if err != nil {
		return nil, err
	}
	if len(hexStr) == 0 {
		return nil, nil
	}
	return big.NewInt(0).SetBytes(common.FromHex(hexStr)), nil
}

// ReadFrom reads  from readBuf and put into struct.
func (st *TransactionData) ReadFrom(readBuf *codec.Reader) error {
	var (
		err    error
		length int32
		have   bool
		ty     byte
	)
	st.ResetDefault()

	err = readBuf.ReadInt32(&st.Version, 1, false)
	if err != nil {
		return err
	}

	err = readBuf.ReadString(&st.ChainID, 2, false)
	if err != nil {
		return err
	}

	err = readBuf.ReadString(&st.GroupID, 3, false)
	if err != nil {
		return err
	}

	err = readBuf.ReadInt64(&st.BlockLimit, 4, false)
	if err != nil {
		return err
	}

	err = readBuf.ReadString(&st.Nonce, 5, false)
	if err != nil {
		return err
	}
	var to string
	err = readBuf.ReadString(&to, 6, false)
	if err != nil {
		return err
	}
	if len(to) > 0 {
		addr := common.HexToAddress(to)
		st.To = &addr
	}

	have, ty, err = readBuf.SkipToNoCheck(7, false)
	if err != nil {
		return err
	}
	if have {
		if ty == codec.LIST {
			err = readBuf.ReadInt32(&length, 0, true)
			if err != nil {
				return err
			}
			st.Input = make([]byte, length)
			for i0, e0 := int32(0), length; i0 < e0; i0++ {
				err = readBuf.ReadUint8(&st.Input[i0], 0, true)
				if err != nil {
					return err
				}
			}
		} else if ty == codec.SimpleList {
			_, err = readBuf.SkipTo(codec.BYTE, 0, true)
			if err != nil {
				return err
			}
			err = readBuf.ReadInt32(&length, 0, true)
			if err != nil {
				return err
			}
			err = readBuf.ReadSliceUint8(&st.Input, length, true)
			if err != nil {
				return err
			}
		} else {
			err = fmt.Errorf("require vector, but not")
			if err != nil {
				return err
			}
		}
	}

	err = readBuf.ReadString(&st.Abi, 8, false)
	if err != nil {
		return err
	}
	st.Value, err = readBigIntFromHex(readBuf, 9, false)
	if err != nil {
		return err
	}
	st.GasPrice, err = readBigIntFromHex(readBuf, 10, false)
	if err != nil {
		return err
	}

	err = readBuf.ReadInt64(&st.GasLimit, 11, false)
	if err != nil {
		return err
	}

	st.MaxFeePerGas, err = readBigIntFromHex(readBuf, 12, false)
	if err != nil {
		return err
	}

	st.MaxPriorityFeePerGas, err = readBigIntFromHex(readBuf, 13, false)
	if err != nil {
		return err
	}

	_ = err
	_ = length
	_ = have
	_ = ty
	return nil
}

// ReadBlock reads struct from the given tag , require or optional.
func (st *TransactionData) ReadBlock(readBuf *codec.Reader, tag byte, require bool) error {
	var (
		err  error
		have bool
	)
	st.ResetDefault()

	have, err = readBuf.SkipTo(codec.StructBegin, tag, require)
	if err != nil {
		return err
	}
	if !have {
		if require {
			return fmt.Errorf("require TransactionData, but not exist. tag %d", tag)
		}
		return nil
	}

	err = st.ReadFrom(readBuf)
	if err != nil {
		return err
	}

	err = readBuf.SkipToStructEnd()
	if err != nil {
		return err
	}
	_ = have
	return nil
}

// WriteTo encode struct to buffer
func (st *TransactionData) WriteTo(buf *codec.Buffer) (err error) {
	// if st.Version != 0 {
	err = buf.WriteInt32(st.Version, 1)
	if err != nil {
		return err
	}
	// }

	if st.ChainID != "" {
		err = buf.WriteString(st.ChainID, 2)
		if err != nil {
			return err
		}
	}

	if st.GroupID != "" {
		err = buf.WriteString(st.GroupID, 3)
		if err != nil {
			return err
		}
	}

	if st.BlockLimit != 0 {
		err = buf.WriteInt64(st.BlockLimit, 4)
		if err != nil {
			return err
		}
	}

	if st.Nonce != "" {
		err = buf.WriteString(st.Nonce, 5)
		if err != nil {
			return err
		}
	}

	if st.To != nil {
		err = buf.WriteString(fmt.Sprintf("%x", st.To), 6)
		if err != nil {
			return err
		}
	}

	if len(st.Input) > 0 {
		err = buf.WriteHead(codec.SimpleList, 7)
		if err != nil {
			return err
		}
		err = buf.WriteHead(codec.BYTE, 0)
		if err != nil {
			return err
		}
		err = buf.WriteInt32(int32(len(st.Input)), 0)
		if err != nil {
			return err
		}
		err = buf.WriteSliceUint8(st.Input)
		if err != nil {
			return err
		}
	}

	if st.Abi != "" {
		err = buf.WriteString(st.Abi, 8)
		if err != nil {
			return err
		}
	}

	if st.Value != nil {
		err = buf.WriteString(fmt.Sprintf("%#x", st.Value), 9)
		if err != nil {
			return err
		}
	}

	if st.GasPrice != nil {
		err = buf.WriteString(fmt.Sprintf("%#x", st.GasPrice), 10)
		if err != nil {
			return err
		}
	}

	if st.GasLimit != 0 {
		err = buf.WriteInt64(st.GasLimit, 11)
		if err != nil {
			return err
		}
	}

	if st.MaxFeePerGas != nil {
		err = buf.WriteString(fmt.Sprintf("%#x", st.MaxFeePerGas), 12)
		if err != nil {
			return err
		}
	}

	if st.MaxPriorityFeePerGas != nil {
		err = buf.WriteString(fmt.Sprintf("%#x", st.MaxPriorityFeePerGas), 13)
		if err != nil {
			return err
		}
	}

	return err
}

// WriteBlock encode struct
func (st *TransactionData) WriteBlock(buf *codec.Buffer, tag byte) error {
	var err error
	err = buf.WriteHead(codec.StructBegin, tag)
	if err != nil {
		return err
	}

	err = st.WriteTo(buf)
	if err != nil {
		return err
	}

	err = buf.WriteHead(codec.StructEnd, 0)
	if err != nil {
		return err
	}
	return nil
}

type Transaction struct {
	Data       TransactionData
	DataHash   *common.Hash    `json:"dataHash" tars:"dataHash,tag:2,require:false"`
	Signature  []byte          `json:"signature" tars:"signature,tag:3,require:false"`
	ImportTime int64           `json:"importTime" tars:"importTime,tag:4,require:false"`
	Attribute  int32           `json:"attribute" tars:"attribute,tag:5,require:false"`
	Sender     *common.Address `json:"sender" tars:"sender,tag:7,require:false"`
	ExtraData  string          `json:"extraData" tars:"extraData,tag:8,require:false"`
	SMCrypto   bool            `json:"-"`
	// Data       TarsTransactionData `json:"data" tars:"data,tag:1,require:false"`
	// Signature values
	V *big.Int `json:"v"`
	R *big.Int `json:"r"`
	S *big.Int `json:"s"`
}

// NewTransaction returns a new transaction
func NewTransaction(to common.Address, amount *big.Int, gasLimit int64, gasPrice *big.Int, blockLimit int64, data []byte, nonce, chainId, groupId, extraData string, smcrypto bool) *Transaction {
	return newTransaction(&to, amount, gasLimit, gasPrice, blockLimit, data, nonce, chainId, groupId, extraData, smcrypto)
}

// NewSimpleTx creates a contract transaction, if nonce is empty string, the nonce will be auto generated
func NewSimpleTx(to *common.Address, data []byte, abi, nonce, extraData string, smcrypto bool) *Transaction {
	if len(data) > 0 {
		data = common.CopyBytes(data)
	}
	d := TransactionData{
		To:    to,
		Input: data,
		Abi:   abi,
		Nonce: nonce,
	}
	return &Transaction{Data: d, SMCrypto: smcrypto, ExtraData: extraData}
}

func newTransaction(to *common.Address, amount *big.Int, gasLimit int64, gasPrice *big.Int, blockLimit int64, data []byte, nonce, chainId, groupId string, extraData string, smcrypto bool) *Transaction {
	if len(data) > 0 {
		data = common.CopyBytes(data)
	}
	d := TransactionData{
		Nonce:      nonce,
		To:         to,
		Input:      data,
		Value:      new(big.Int),
		GasLimit:   gasLimit,
		BlockLimit: blockLimit,
		GasPrice:   new(big.Int),
		ChainID:    chainId,
		GroupID:    groupId,
	}
	if amount != nil {
		d.Value = big.NewInt(0).Set(amount)
	}
	if gasPrice != nil {
		d.GasPrice = big.NewInt(0).Set(gasPrice)
	}
	return &Transaction{Data: d, SMCrypto: smcrypto, ExtraData: extraData}
}

// Protected returns whether the transaction is protected from replay protection.
func (tx *Transaction) Protected() bool {
	return isProtectedV(tx.V)
}

func isProtectedV(V *big.Int) bool {
	if V.BitLen() <= 8 {
		v := V.Uint64()
		return v != 27 && v != 28
	}
	// anything not 27 or 28 is considered protected
	return true
}

func (tx *Transaction) Input() []byte      { return common.CopyBytes(tx.Data.Input) }
func (tx *Transaction) ABI() string        { return tx.Data.Abi }
func (tx *Transaction) GasPrice() *big.Int { return new(big.Int).Set(tx.Data.GasPrice) }
func (tx *Transaction) Value() *big.Int    { return new(big.Int).Set(tx.Data.Value) }
func (tx *Transaction) Nonce() string      { return tx.Data.Nonce }
func (tx *Transaction) CheckNonce() bool   { return true }

// To returns the recipient address of the transaction.
// It returns nil if the transaction is a contract creation.
func (tx *Transaction) To() *common.Address {
	if tx.Data.To == nil {
		return nil
	}
	to := *tx.Data.To
	return &to
}

// Hash hashes the RLP encoding of tx.
// It uniquely identifies the transaction.
func (tx *Transaction) Hash() common.Hash {
	// if hash := tx.DataHash; hash != nil {
	// 	return *hash
	// }
	var v common.Hash
	if tx.SMCrypto {
		v = tx.sm3Hash()
	} else {
		v = tx.keccak256Hash()
	}
	tx.DataHash = &v
	return *tx.DataHash
}

// SM3HashNonSig hashes the RLP encoding of tx use sm3.
// It uniquely identifies the transaction.
func (tx *Transaction) sm3Hash() (h common.Hash) {
	var sm3 sm3.Context
	sm3.Reset()
	version := make([]byte, 4)
	binary.BigEndian.PutUint32(version, uint32(tx.Data.Version))
	sm3.Append(version)
	sm3.Append([]byte(tx.Data.ChainID))
	sm3.Append([]byte(tx.Data.GroupID))
	blockLimit := make([]byte, 8)
	binary.BigEndian.PutUint64(blockLimit, uint64(tx.Data.BlockLimit))
	sm3.Append(blockLimit)
	sm3.Append([]byte(tx.Data.Nonce))
	if tx.Data.To != nil {
		sm3.Append([]byte(fmt.Sprintf("%x", tx.Data.To)))
	}
	sm3.Append(tx.Data.Input)
	sm3.Append([]byte(tx.Data.Abi))
	if tx.Data.Version == 1 {
		if tx.Data.Value != nil {
			sm3.Append([]byte(fmt.Sprintf("%x", tx.Data.Value)))
		}
		if tx.Data.GasPrice != nil {
			sm3.Append([]byte(fmt.Sprintf("%x", tx.Data.GasPrice)))
		}
		gasLimit := make([]byte, 8)
		binary.BigEndian.PutUint64(gasLimit, uint64(tx.Data.GasLimit))
		sm3.Append(gasLimit)
		if tx.Data.MaxFeePerGas != nil {
			sm3.Append([]byte(fmt.Sprintf("%x", tx.Data.MaxFeePerGas)))
		}
		if tx.Data.MaxPriorityFeePerGas != nil {
			sm3.Append([]byte(fmt.Sprintf("%x", tx.Data.MaxPriorityFeePerGas)))
		}
	}
	hash := sm3.Final()
	copy(h[:], hash)
	return h
}

func (tx *Transaction) keccak256Hash() (h common.Hash) {
	hw := sha3.NewLegacyKeccak256()
	version := make([]byte, 4)
	binary.BigEndian.PutUint32(version, uint32(tx.Data.Version))
	hw.Write(version)
	hw.Write([]byte(tx.Data.ChainID))
	hw.Write([]byte(tx.Data.GroupID))
	blockLimit := make([]byte, 8)
	binary.BigEndian.PutUint64(blockLimit, uint64(tx.Data.BlockLimit))
	hw.Write(blockLimit)
	hw.Write([]byte(tx.Data.Nonce))
	if tx.Data.To != nil {
		hw.Write([]byte(fmt.Sprintf("%x", tx.Data.To)))
	}
	hw.Write(tx.Data.Input)
	hw.Write([]byte(tx.Data.Abi))
	if tx.Data.Version == 1 {
		if tx.Data.Value != nil {
			hw.Write([]byte(fmt.Sprintf("%x", tx.Data.Value)))
		}
		if tx.Data.GasPrice != nil {
			hw.Write([]byte(fmt.Sprintf("%x", tx.Data.GasPrice)))
		}
		gasLimit := make([]byte, 8)
		binary.BigEndian.PutUint64(gasLimit, uint64(tx.Data.GasLimit))
		hw.Write(gasLimit)
		if tx.Data.MaxFeePerGas != nil {
			hw.Write([]byte(fmt.Sprintf("%x", tx.Data.MaxFeePerGas)))
		}
		if tx.Data.MaxPriorityFeePerGas != nil {
			hw.Write([]byte(fmt.Sprintf("%x", tx.Data.MaxPriorityFeePerGas)))
		}
	}
	var v []byte
	v = hw.Sum(v)
	copy(h[:], v)
	return h
}

// WithSignature returns a new transaction with the given signature.
// This signature needs to be in the [R || S || V] format where V is 0 or 1.
func (tx *Transaction) WithSignature(signer Signer, sig []byte) (*Transaction, error) {
	r, s, v, err := signer.SignatureValues(tx, sig)
	if err != nil {
		return nil, err
	}
	cpy := &Transaction{Data: tx.Data}
	cpy.R, cpy.S, cpy.V = r, s, v
	cpy.SMCrypto = tx.SMCrypto
	return cpy, nil
}

// WithSM2Signature returns a new transaction with the given signature.
// This signature needs to be in the [R || S || V] format where V is 0 or 1.
func (tx *Transaction) WithSM2Signature(signer Signer, sig []byte) (*Transaction, error) {
	if len(sig) != 128 {
		panic(fmt.Sprintf("wrong size for SM2Signature: got %d, want 128", len(sig)))
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:64])
	v := new(big.Int).SetBytes(sig[64:])
	cpy := &Transaction{Data: tx.Data}
	cpy.R, cpy.S, cpy.V = r, s, v
	cpy.SMCrypto = tx.SMCrypto
	return cpy, nil
}

// Cost returns amount + gasprice * gaslimit.
func (tx *Transaction) Cost() *big.Int {
	total := new(big.Int).Mul(tx.Data.GasPrice, new(big.Int).SetInt64(tx.Data.GasLimit))
	total.Add(total, tx.Data.Value)
	return total
}

// SignatureValues returns the V, R, S signature values of the transaction.
// The return values should not be modified by the caller.
func (tx *Transaction) SignatureValues() (v, r, s *big.Int) {
	return tx.V, tx.R, tx.S
}

func (st *Transaction) ResetDefault() {
	st.Data.ResetDefault()
}

func (st *Transaction) Bytes() []byte {
	buf := codec.NewBuffer()
	st.WriteTo(buf)
	return buf.ToBytes()
}

// ReadFrom reads  from readBuf and put into struct.
func (st *Transaction) ReadFrom(readBuf *codec.Reader) error {
	var (
		err    error
		length int32
		have   bool
		ty     byte
	)
	st.ResetDefault()

	err = st.Data.ReadBlock(readBuf, 1, false)
	if err != nil {
		return err
	}

	have, ty, err = readBuf.SkipToNoCheck(2, false)
	if err != nil {
		return err
	}
	if have {
		if ty == codec.LIST {
			err = readBuf.ReadInt32(&length, 0, true)
			if err != nil {
				return err
			}
			st.DataHash = new(common.Hash)
			for i0, e0 := int32(0), length; i0 < e0; i0++ {
				err = readBuf.ReadUint8(&st.DataHash[i0], 0, true)
				if err != nil {
					return err
				}
			}
		} else if ty == codec.SimpleList {
			_, err = readBuf.SkipTo(codec.BYTE, 0, true)
			if err != nil {
				return err
			}
			err = readBuf.ReadInt32(&length, 0, true)
			if err != nil {
				return err
			}
			var data []byte
			err = readBuf.ReadSliceUint8(&data, length, true)
			if err != nil {
				return err
			}
			dataHash := common.BytesToHash(data)
			st.DataHash = &dataHash
		} else {
			err = fmt.Errorf("require vector, but not")
			if err != nil {
				return err
			}
		}
	}

	have, ty, err = readBuf.SkipToNoCheck(3, false)
	if err != nil {
		return err
	}
	if have {
		if ty == codec.LIST {
			err = readBuf.ReadInt32(&length, 0, true)
			if err != nil {
				return err
			}
			st.Signature = make([]byte, length)
			for i1, e1 := int32(0), length; i1 < e1; i1++ {
				err = readBuf.ReadUint8(&st.Signature[i1], 0, true)
				if err != nil {
					return err
				}
			}
		} else if ty == codec.SimpleList {
			_, err = readBuf.SkipTo(codec.BYTE, 0, true)
			if err != nil {
				return err
			}
			err = readBuf.ReadInt32(&length, 0, true)
			if err != nil {
				return err
			}
			err = readBuf.ReadSliceUint8(&st.Signature, length, true)
			if err != nil {
				return err
			}
		} else {
			err = fmt.Errorf("require vector, but not")
			if err != nil {
				return err
			}
		}
	}

	err = readBuf.ReadInt64(&st.ImportTime, 4, false)
	if err != nil {
		return err
	}

	err = readBuf.ReadInt32(&st.Attribute, 5, false)
	if err != nil {
		return err
	}

	have, ty, err = readBuf.SkipToNoCheck(7, false)
	if err != nil {
		return err
	}
	if have {
		if ty == codec.LIST {
			err = readBuf.ReadInt32(&length, 0, true)
			if err != nil {
				return err
			}
			st.Sender = new(common.Address)
			for i2, e2 := int32(0), length; i2 < e2; i2++ {
				err = readBuf.ReadUint8(&st.Sender[i2], 0, true)
				if err != nil {
					return err
				}
			}
		} else if ty == codec.SimpleList {
			_, err = readBuf.SkipTo(codec.BYTE, 0, true)
			if err != nil {
				return err
			}
			err = readBuf.ReadInt32(&length, 0, true)
			if err != nil {
				return err
			}
			var sender []byte
			err = readBuf.ReadSliceUint8(&sender, length, true)
			if err != nil {
				return err
			}
			senderAddr := common.BytesToAddress(sender)
			st.Sender = &senderAddr
		} else {
			err = fmt.Errorf("require vector, but not")
			if err != nil {
				return err
			}
		}
	}

	err = readBuf.ReadString(&st.ExtraData, 8, false)
	if err != nil {
		return err
	}

	_ = err
	_ = length
	_ = have
	_ = ty
	return nil
}

// ReadBlock reads struct from the given tag , require or optional.
func (st *Transaction) ReadBlock(readBuf *codec.Reader, tag byte, require bool) error {
	var (
		err  error
		have bool
	)
	st.ResetDefault()

	have, err = readBuf.SkipTo(codec.StructBegin, tag, require)
	if err != nil {
		return err
	}
	if !have {
		if require {
			return fmt.Errorf("require Transaction, but not exist. tag %d", tag)
		}
		return nil
	}

	err = st.ReadFrom(readBuf)
	if err != nil {
		return err
	}

	err = readBuf.SkipToStructEnd()
	if err != nil {
		return err
	}
	_ = have
	return nil
}

// WriteTo encode struct to buffer
func (st *Transaction) WriteTo(buf *codec.Buffer) (err error) {
	err = st.Data.WriteBlock(buf, 1)
	if err != nil {
		return err
	}

	if len(st.DataHash) > 0 {
		err = buf.WriteHead(codec.SimpleList, 2)
		if err != nil {
			return err
		}
		err = buf.WriteHead(codec.BYTE, 0)
		if err != nil {
			return err
		}
		err = buf.WriteInt32(int32(len(st.DataHash)), 0)
		if err != nil {
			return err
		}
		err = buf.WriteSliceUint8(st.DataHash.Bytes())
		if err != nil {
			return err
		}
	}

	if len(st.Signature) > 0 {
		err = buf.WriteHead(codec.SimpleList, 3)
		if err != nil {
			return err
		}
		err = buf.WriteHead(codec.BYTE, 0)
		if err != nil {
			return err
		}
		err = buf.WriteInt32(int32(len(st.Signature)), 0)
		if err != nil {
			return err
		}
		err = buf.WriteSliceUint8(st.Signature)
		if err != nil {
			return err
		}
	}

	if st.ImportTime != 0 {
		err = buf.WriteInt64(st.ImportTime, 4)
		if err != nil {
			return err
		}
	}

	if st.Attribute != 0 {
		err = buf.WriteInt32(st.Attribute, 5)
		if err != nil {
			return err
		}
	}

	if len(st.Sender) > 0 {
		err = buf.WriteHead(codec.SimpleList, 7)
		if err != nil {
			return err
		}
		err = buf.WriteHead(codec.BYTE, 0)
		if err != nil {
			return err
		}
		err = buf.WriteInt32(int32(len(st.Sender)), 0)
		if err != nil {
			return err
		}
		err = buf.WriteSliceUint8(st.Sender.Bytes())
		if err != nil {
			return err
		}
	}

	if st.ExtraData != "" {
		err = buf.WriteString(st.ExtraData, 8)
		if err != nil {
			return err
		}
	}

	return err
}

// WriteBlock encode struct
func (st *Transaction) WriteBlock(buf *codec.Buffer, tag byte) error {
	var err error
	err = buf.WriteHead(codec.StructBegin, tag)
	if err != nil {
		return err
	}

	err = st.WriteTo(buf)
	if err != nil {
		return err
	}

	err = buf.WriteHead(codec.StructEnd, 0)
	if err != nil {
		return err
	}
	return nil
}

// Transactions is a Transaction slice type for basic sorting.
type Transactions []*Transaction

// Len returns the length of s.
func (s Transactions) Len() int { return len(s) }

// Swap swaps the i'th and the j'th element in s.
func (s Transactions) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

// TxDifference returns a new set which is the difference between a and b.
func TxDifference(a, b Transactions) Transactions {
	keep := make(Transactions, 0, len(a))

	remove := make(map[common.Hash]struct{})
	for _, tx := range b {
		remove[tx.Hash()] = struct{}{}
	}

	for _, tx := range a {
		if _, ok := remove[tx.Hash()]; !ok {
			keep = append(keep, tx)
		}
	}

	return keep
}
