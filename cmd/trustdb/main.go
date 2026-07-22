package main

import (
	"fmt"
	"os"

	"github.com/wowtrust/trustdb/internal/trusterr"
)

func main() {
	if err := newRootCommand(os.Stdout, os.Stderr).Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(trusterr.ExitCode(err))
	}
}
