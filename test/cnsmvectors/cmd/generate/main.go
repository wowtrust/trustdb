package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/wowtrust/trustdb/test/cnsmvectors"
)

func main() {
	check := flag.Bool("check", false, "fail if the committed corpus differs from a clean regeneration")
	write := flag.Bool("write", false, "replace the committed corpus and checksum")
	flag.Parse()
	if *check == *write {
		fatalf("select exactly one of -check or -write")
	}
	root, err := repositoryRoot()
	if err != nil {
		fatalf("%v", err)
	}
	workDir, err := os.MkdirTemp("", "trustdb-cn-sm-vectors-*")
	if err != nil {
		fatalf("create generation workspace: %v", err)
	}
	defer os.RemoveAll(workDir)
	corpus, err := cnsmvectors.Generate(workDir)
	if err != nil {
		fatalf("generate corpus: %v", err)
	}
	data, err := cnsmvectors.CanonicalJSON(corpus)
	if err != nil {
		fatalf("encode corpus: %v", err)
	}
	checksum := []byte(cnsmvectors.Checksum(data))
	corpusPath := filepath.Join(root, "test", "cnsmvectors", cnsmvectors.CorpusName)
	checksumPath := filepath.Join(root, "test", "cnsmvectors", cnsmvectors.ChecksumName)
	if *write {
		if err := os.WriteFile(corpusPath, data, 0o644); err != nil {
			fatalf("write corpus: %v", err)
		}
		if err := os.WriteFile(checksumPath, checksum, 0o644); err != nil {
			fatalf("write checksum: %v", err)
		}
		fmt.Printf("wrote %s and %s\n", corpusPath, checksumPath)
		return
	}
	committed, err := os.ReadFile(corpusPath)
	if err != nil {
		fatalf("read committed corpus: %v", err)
	}
	committedChecksum, err := os.ReadFile(checksumPath)
	if err != nil {
		fatalf("read committed checksum: %v", err)
	}
	if !bytes.Equal(committed, data) || !bytes.Equal(committedChecksum, checksum) {
		fatalf("CN_SM_V1 vector drift detected; regenerate with -write and obtain explicit suite/format review")
	}
	fmt.Println("CN_SM_V1 interoperability corpus is reproducible and unchanged")
}

func repositoryRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("repository root not found")
		}
		dir = parent
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "cn-sm-vector-generator: "+format+"\n", args...)
	os.Exit(1)
}
