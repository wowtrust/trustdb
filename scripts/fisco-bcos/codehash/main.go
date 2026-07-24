// Command codehash computes the chain-native runtime code hash recorded for a
// TrustDB FISCO BCOS contract artifact.
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/emmansun/gmsm/sm3"
	"golang.org/x/crypto/sha3"
)

func main() {
	algorithm := flag.String("algorithm", "", "keccak256 or sm3")
	hexFile := flag.String("hex-file", "", "file containing hexadecimal EVM bytecode")
	flag.Parse()
	if *hexFile == "" {
		fatalf("--hex-file is required")
	}
	encoded, err := os.ReadFile(*hexFile)
	if err != nil {
		fatalf("read bytecode: %v", err)
	}
	code, err := hex.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		fatalf("decode bytecode: %v", err)
	}

	var digest []byte
	switch *algorithm {
	case "keccak256":
		hash := sha3.NewLegacyKeccak256()
		_, _ = hash.Write(code)
		digest = hash.Sum(nil)
	case "sm3":
		sum := sm3.Sum(code)
		digest = sum[:]
	default:
		fatalf("--algorithm must be keccak256 or sm3")
	}
	fmt.Println(hex.EncodeToString(digest))
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(2)
}
