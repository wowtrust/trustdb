package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/wowtrust/trustdb/internal/tlcpprofile"
)

type stringList []string

func (values *stringList) String() string { return strings.Join(*values, ",") }

func (values *stringList) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return errors.New("value must not be empty")
	}
	*values = append(*values, value)
	return nil
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] != "validate" {
		return errors.New("usage: trustdb-tlcp-profile validate --profile /absolute/path/profile.json [--forbid-key-ref REF]")
	}
	flags := flag.NewFlagSet("validate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var profilePath string
	var forbidden stringList
	flags.StringVar(&profilePath, "profile", "", "absolute path to a TLCP gateway profile")
	flags.Var(&forbidden, "forbid-key-ref", "proof-signing key reference that the gateway must not reuse; may be repeated")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	profilePath = strings.TrimSpace(profilePath)
	if profilePath == "" {
		return errors.New("--profile is required")
	}
	_, report, err := tlcpprofile.LoadAndValidate(profilePath, tlcpprofile.Options{
		ForbiddenKeyReferences: append([]string(nil), forbidden...),
	})
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(report); err != nil {
		return fmt.Errorf("encode TLCP gateway validation report: %w", err)
	}
	return nil
}
