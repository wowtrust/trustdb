package fiscobcos

import (
	"encoding/binary"
	"fmt"
	"math"
)

const (
	tarsByte        = 0
	tarsShort       = 1
	tarsInt         = 2
	tarsLong        = 3
	tarsFloat       = 4
	tarsDouble      = 5
	tarsString1     = 6
	tarsString4     = 7
	tarsMap         = 8
	tarsList        = 9
	tarsStructBegin = 10
	tarsStructEnd   = 11
	tarsZero        = 12
	tarsSimpleList  = 13

	maxTARSDepth  = 32
	maxTARSValues = 1 << 16

	transactionDataHashTag = 2
	transactionSenderTag   = 7
	transactionHashBytes   = 32
	transactionSenderBytes = 20
)

// validateBoundedTARS walks an untrusted TARS value before the official SDK
// decoder sees it. The SDK-generated reader allocates from wire lengths, so
// this preflight proves every length and collection count fits the already
// bounded input and prevents attacker-controlled oversized allocations.
func validateBoundedTARS(data []byte) error {
	if len(data) == 0 || len(data) > maxRawTransactionBytes {
		return fmt.Errorf("%w: TARS transaction size is invalid", ErrInvalidProof)
	}
	p := tarsPreflight{data: data, remainingValues: maxTARSValues}
	for p.offset < len(data) {
		if err := p.value(0, false); err != nil {
			return err
		}
	}
	if p.offset != len(data) {
		return fmt.Errorf("%w: TARS transaction has trailing bytes", ErrInvalidProof)
	}
	return nil
}

// validateTransactionTARSSchema protects the fixed-size fields used by the
// pinned generated Transaction reader. That reader accepts LIST as well as
// SimpleList, but writes LIST elements directly into common.Hash and
// common.Address arrays before checking their lengths. Requiring the exact
// canonical SimpleList representation here prevents those writes from ever
// indexing past the fixed arrays.
func validateTransactionTARSSchema(data []byte) error {
	p := tarsPreflight{data: data, remainingValues: maxTARSValues}
	seenDataHash := false
	seenSender := false
	for p.offset < len(data) {
		kind, tag, err := p.startValue(0)
		if err != nil {
			return err
		}
		switch tag {
		case transactionDataHashTag:
			if seenDataHash {
				return fmt.Errorf("%w: duplicate TARS transaction data hash", ErrInvalidProof)
			}
			seenDataHash = true
			if err := p.fixedByteSimpleList(
				kind,
				transactionHashBytes,
				"transaction data hash",
			); err != nil {
				return err
			}
		case transactionSenderTag:
			if seenSender {
				return fmt.Errorf("%w: duplicate TARS transaction sender", ErrInvalidProof)
			}
			seenSender = true
			if err := p.fixedByteSimpleList(
				kind,
				transactionSenderBytes,
				"transaction sender",
			); err != nil {
				return err
			}
		default:
			if err := p.valueBody(kind, 0, false); err != nil {
				return err
			}
		}
	}
	return nil
}

type tarsPreflight struct {
	data            []byte
	offset          int
	remainingValues int
}

func (p *tarsPreflight) value(depth int, allowStructEnd bool) error {
	kind, _, err := p.startValue(depth)
	if err != nil {
		return err
	}
	return p.valueBody(kind, depth, allowStructEnd)
}

func (p *tarsPreflight) startValue(depth int) (int, int, error) {
	if depth > maxTARSDepth || p.remainingValues <= 0 {
		return 0, 0, fmt.Errorf("%w: TARS nesting or value count exceeds bounds", ErrInvalidProof)
	}
	p.remainingValues--
	return p.headWithTag()
}

func (p *tarsPreflight) valueBody(kind int, depth int, allowStructEnd bool) error {
	switch kind {
	case tarsByte:
		return p.skip(1)
	case tarsShort:
		return p.skip(2)
	case tarsInt, tarsFloat:
		return p.skip(4)
	case tarsLong, tarsDouble:
		return p.skip(8)
	case tarsString1:
		if err := p.require(1); err != nil {
			return err
		}
		length := int(p.data[p.offset])
		p.offset++
		return p.skip(length)
	case tarsString4:
		length, err := p.fixedLength()
		if err != nil {
			return err
		}
		return p.skip(length)
	case tarsMap:
		count, err := p.integerValue()
		if err != nil || count < 0 || count > int64(p.remainingValues/2) {
			return fmt.Errorf("%w: invalid TARS map count", ErrInvalidProof)
		}
		for i := int64(0); i < count*2; i++ {
			if err := p.value(depth+1, false); err != nil {
				return err
			}
		}
		return nil
	case tarsList:
		count, err := p.integerValue()
		if err != nil || count < 0 || count > int64(p.remainingValues) {
			return fmt.Errorf("%w: invalid TARS list count", ErrInvalidProof)
		}
		for i := int64(0); i < count; i++ {
			if err := p.value(depth+1, false); err != nil {
				return err
			}
		}
		return nil
	case tarsStructBegin:
		for {
			if err := p.require(1); err != nil {
				return err
			}
			nextKind := int(p.data[p.offset] & 0x0f)
			if nextKind == tarsStructEnd {
				_, err := p.head()
				return err
			}
			if err := p.value(depth+1, true); err != nil {
				return err
			}
		}
	case tarsStructEnd:
		if allowStructEnd {
			return nil
		}
		return fmt.Errorf("%w: unexpected TARS struct end", ErrInvalidProof)
	case tarsZero:
		return nil
	case tarsSimpleList:
		elementKind, elementTag, err := p.headWithTag()
		if err != nil || elementKind != tarsByte || elementTag != 0 {
			return fmt.Errorf("%w: unsupported TARS simple-list element", ErrInvalidProof)
		}
		length, err := p.integerValue()
		if err != nil || length < 0 || length > int64(len(p.data)-p.offset) {
			return fmt.Errorf("%w: invalid TARS simple-list length", ErrInvalidProof)
		}
		return p.skip(int(length))
	default:
		return fmt.Errorf("%w: unsupported TARS type %d", ErrInvalidProof, kind)
	}
}

func (p *tarsPreflight) fixedByteSimpleList(kind int, length int, name string) error {
	if kind != tarsSimpleList {
		return fmt.Errorf("%w: %s must use canonical TARS SimpleList", ErrInvalidProof, name)
	}
	elementKind, elementTag, err := p.headWithTag()
	if err != nil || elementKind != tarsByte || elementTag != 0 {
		return fmt.Errorf("%w: %s has an invalid TARS element type", ErrInvalidProof, name)
	}
	actual, err := p.integerValue()
	if err != nil || actual != int64(length) {
		return fmt.Errorf(
			"%w: %s must contain exactly %d bytes",
			ErrInvalidProof,
			name,
			length,
		)
	}
	return p.skip(length)
}

func (p *tarsPreflight) head() (int, error) {
	kind, _, err := p.headWithTag()
	return kind, err
}

func (p *tarsPreflight) headWithTag() (int, int, error) {
	if err := p.require(1); err != nil {
		return 0, 0, err
	}
	head := p.data[p.offset]
	p.offset++
	tag := int(head >> 4)
	if tag == 15 {
		if err := p.require(1); err != nil {
			return 0, 0, err
		}
		tag = int(p.data[p.offset])
		p.offset++
	}
	return int(head & 0x0f), tag, nil
}

func (p *tarsPreflight) integerValue() (int64, error) {
	kind, err := p.head()
	if err != nil {
		return 0, err
	}
	switch kind {
	case tarsZero:
		return 0, nil
	case tarsByte:
		if err := p.require(1); err != nil {
			return 0, err
		}
		value := int64(int8(p.data[p.offset]))
		p.offset++
		return value, nil
	case tarsShort:
		if err := p.require(2); err != nil {
			return 0, err
		}
		value := int64(int16(binary.BigEndian.Uint16(p.data[p.offset:])))
		p.offset += 2
		return value, nil
	case tarsInt:
		if err := p.require(4); err != nil {
			return 0, err
		}
		value := int64(int32(binary.BigEndian.Uint32(p.data[p.offset:])))
		p.offset += 4
		return value, nil
	case tarsLong:
		if err := p.require(8); err != nil {
			return 0, err
		}
		value := binary.BigEndian.Uint64(p.data[p.offset:])
		p.offset += 8
		if value > math.MaxInt64 {
			return 0, fmt.Errorf("%w: negative or overflowing TARS length", ErrInvalidProof)
		}
		return int64(value), nil
	default:
		return 0, fmt.Errorf("%w: non-integer TARS length", ErrInvalidProof)
	}
}

func (p *tarsPreflight) fixedLength() (int, error) {
	if err := p.require(4); err != nil {
		return 0, err
	}
	value := binary.BigEndian.Uint32(p.data[p.offset:])
	p.offset += 4
	if uint64(value) > uint64(len(p.data)-p.offset) {
		return 0, fmt.Errorf("%w: TARS string length exceeds input", ErrInvalidProof)
	}
	return int(value), nil
}

func (p *tarsPreflight) skip(length int) error {
	if length < 0 {
		return fmt.Errorf("%w: negative TARS length", ErrInvalidProof)
	}
	if err := p.require(length); err != nil {
		return err
	}
	p.offset += length
	return nil
}

func (p *tarsPreflight) require(length int) error {
	if length < 0 || length > len(p.data)-p.offset {
		return fmt.Errorf("%w: truncated TARS transaction", ErrInvalidProof)
	}
	return nil
}
