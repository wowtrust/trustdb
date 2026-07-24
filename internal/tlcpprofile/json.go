package tlcpprofile

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	maxJSONDepth       = 16
	maxJSONObjectKeys  = 128
	maxJSONArrayValues = 128
)

// validateJSONStructure rejects duplicate object keys before encoding/json
// populates a struct. The input byte limit is applied by Decode before this
// parser runs.
func validateJSONStructure(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := consumeJSONValue(decoder, 0); err != nil {
		return fmt.Errorf("decode TLCP gateway profile: %w", err)
	}
	if token, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("decode TLCP gateway profile: trailing token %v", token)
		}
		return fmt.Errorf("decode TLCP gateway profile: %w", err)
	}
	return nil
}

func consumeJSONValue(decoder *json.Decoder, depth int) error {
	if depth > maxJSONDepth {
		return errors.New("JSON nesting exceeds limit")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate JSON object key %q", key)
			}
			if len(seen) >= maxJSONObjectKeys {
				return errors.New("JSON object key count exceeds limit")
			}
			seen[key] = struct{}{}
			if err := consumeJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("JSON object is not terminated")
		}
	case '[':
		count := 0
		for decoder.More() {
			if count >= maxJSONArrayValues {
				return errors.New("JSON array length exceeds limit")
			}
			if err := consumeJSONValue(decoder, depth+1); err != nil {
				return err
			}
			count++
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("JSON array is not terminated")
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
	return nil
}
