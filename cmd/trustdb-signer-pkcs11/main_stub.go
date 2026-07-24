//go:build !pkcs11 || !cgo

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "trustdb PKCS#11 signer requires CGO_ENABLED=1 and -tags=pkcs11")
	os.Exit(1)
}
