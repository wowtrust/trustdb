package main

import (
	"context"

	"github.com/wowtrust/trustdb/internal/globallog"
	"github.com/wowtrust/trustdb/internal/trusterr"
	"github.com/spf13/cobra"
)

func newGlobalLogCommand(rt *runtimeConfig) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "global-log",
		Short: "Inspect TrustDB global transparency log STHs and proofs",
	}
	cmd.AddCommand(newGlobalLogSTHCommand(rt))
	cmd.AddCommand(newGlobalLogProofCommand(rt))
	cmd.AddCommand(newGlobalLogCompactCommand(rt))
	return cmd
}

func newGlobalLogSTHCommand(rt *runtimeConfig) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sth",
		Short: "Inspect signed tree heads",
	}
	cmd.AddCommand(newGlobalLogSTHLatestCommand(rt))
	cmd.AddCommand(newGlobalLogSTHGetCommand(rt))
	return cmd
}

func newGlobalLogSTHLatestCommand(rt *runtimeConfig) *cobra.Command {
	var metastoreKind, metastorePath, proofDir string
	cmd := &cobra.Command{
		Use:   "latest",
		Short: "Print the latest global log SignedTreeHead",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, closeFn, err := openProofStoreForCLI(metastoreKind, metastorePath, proofDir, rt.cfg.Paths.ProofDir)
			if err != nil {
				return err
			}
			defer closeFn()
			sth, ok, err := store.LatestSignedTreeHead(context.Background())
			if err != nil {
				return err
			}
			if !ok {
				return trusterr.New(trusterr.CodeNotFound, "signed tree head not found")
			}
			return rt.writeJSON(sth)
		},
	}
	addProofStoreFlags(cmd, &metastoreKind, &metastorePath, &proofDir)
	return cmd
}

func newGlobalLogSTHGetCommand(rt *runtimeConfig) *cobra.Command {
	var metastoreKind, metastorePath, proofDir string
	var treeSize uint64
	cmd := &cobra.Command{
		Use:   "get",
		Short: "Print a global log SignedTreeHead by tree size",
		RunE: func(cmd *cobra.Command, args []string) error {
			if treeSize == 0 {
				return usageError("global-log sth get requires --tree-size")
			}
			store, closeFn, err := openProofStoreForCLI(metastoreKind, metastorePath, proofDir, rt.cfg.Paths.ProofDir)
			if err != nil {
				return err
			}
			defer closeFn()
			sth, ok, err := store.GetSignedTreeHead(context.Background(), treeSize)
			if err != nil {
				return err
			}
			if !ok {
				return trusterr.New(trusterr.CodeNotFound, "signed tree head not found")
			}
			return rt.writeJSON(sth)
		},
	}
	addProofStoreFlags(cmd, &metastoreKind, &metastorePath, &proofDir)
	cmd.Flags().Uint64Var(&treeSize, "tree-size", 0, "STH tree size")
	return cmd
}

func newGlobalLogProofCommand(rt *runtimeConfig) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "proof",
		Short: "Build global log inclusion and consistency proofs",
	}
	cmd.AddCommand(newGlobalLogInclusionCommand(rt))
	cmd.AddCommand(newGlobalLogConsistencyCommand(rt))
	return cmd
}

func newGlobalLogInclusionCommand(rt *runtimeConfig) *cobra.Command {
	var metastoreKind, metastorePath, proofDir, batchID, outPath, format string
	var treeSize uint64
	cmd := &cobra.Command{
		Use:   "inclusion",
		Short: "Build a global log inclusion proof for a batch id",
		RunE: func(cmd *cobra.Command, args []string) error {
			if batchID == "" {
				return usageError("global-log proof inclusion requires --batch-id")
			}
			store, closeFn, err := openProofStoreForCLI(metastoreKind, metastorePath, proofDir, rt.cfg.Paths.ProofDir)
			if err != nil {
				return err
			}
			defer closeFn()
			svc, err := globallog.NewReader(store)
			if err != nil {
				return err
			}
			proof, err := svc.InclusionProof(context.Background(), batchID, treeSize)
			if err != nil {
				return err
			}
			resolvedFormat, err := writeExportObject(rt, outPath, format, proof)
			if err != nil {
				return err
			}
			if outPath == "" {
				return nil
			}
			return rt.writeJSON(struct {
				BatchID     string `json:"batch_id"`
				TreeSize    uint64 `json:"tree_size"`
				GlobalProof string `json:"global_proof"`
				Format      string `json:"format"`
			}{
				BatchID:     proof.BatchID,
				TreeSize:    proof.TreeSize,
				GlobalProof: outPath,
				Format:      resolvedFormat,
			})
		},
	}
	addProofStoreFlags(cmd, &metastoreKind, &metastorePath, &proofDir)
	cmd.Flags().StringVar(&batchID, "batch-id", "", "batch id to prove")
	cmd.Flags().Uint64Var(&treeSize, "tree-size", 0, "target STH tree size (0 = latest)")
	cmd.Flags().StringVar(&outPath, "out", "", "write proof to file (default format: cbor when --out is set, json otherwise)")
	cmd.Flags().StringVar(&format, "format", "", "output format: json or cbor")
	return cmd
}

func newGlobalLogConsistencyCommand(rt *runtimeConfig) *cobra.Command {
	var metastoreKind, metastorePath, proofDir, outPath, format string
	var from, to uint64
	cmd := &cobra.Command{
		Use:   "consistency",
		Short: "Build a consistency proof between two STH tree sizes",
		RunE: func(cmd *cobra.Command, args []string) error {
			if from == 0 || to == 0 {
				return usageError("global-log proof consistency requires --from and --to")
			}
			store, closeFn, err := openProofStoreForCLI(metastoreKind, metastorePath, proofDir, rt.cfg.Paths.ProofDir)
			if err != nil {
				return err
			}
			defer closeFn()
			svc, err := globallog.NewReader(store)
			if err != nil {
				return err
			}
			proof, err := svc.ConsistencyProof(context.Background(), from, to)
			if err != nil {
				return err
			}
			resolvedFormat, err := writeExportObject(rt, outPath, format, proof)
			if err != nil {
				return err
			}
			if outPath == "" {
				return nil
			}
			return rt.writeJSON(struct {
				FromTreeSize     uint64 `json:"from_tree_size"`
				ToTreeSize       uint64 `json:"to_tree_size"`
				ConsistencyProof string `json:"consistency_proof"`
				Format           string `json:"format"`
			}{
				FromTreeSize:     proof.FromTreeSize,
				ToTreeSize:       proof.ToTreeSize,
				ConsistencyProof: outPath,
				Format:           resolvedFormat,
			})
		},
	}
	addProofStoreFlags(cmd, &metastoreKind, &metastorePath, &proofDir)
	cmd.Flags().Uint64Var(&from, "from", 0, "older STH tree size")
	cmd.Flags().Uint64Var(&to, "to", 0, "newer STH tree size")
	cmd.Flags().StringVar(&outPath, "out", "", "write proof to file (default format: cbor when --out is set, json otherwise)")
	cmd.Flags().StringVar(&format, "format", "", "output format: json or cbor")
	return cmd
}

func newGlobalLogCompactCommand(rt *runtimeConfig) *cobra.Command {
	var metastoreKind, metastorePath, proofDir string
	var tileSize uint64
	cmd := &cobra.Command{
		Use:   "compact",
		Short: "Write compact history tiles for global log leaves",
		RunE: func(cmd *cobra.Command, args []string) error {
			if tileSize == 0 {
				tileSize = rt.cfg.History.TileSize
			}
			store, closeFn, err := openProofStoreForCLI(metastoreKind, metastorePath, proofDir, rt.cfg.Paths.ProofDir)
			if err != nil {
				return err
			}
			defer closeFn()
			svc, err := globallog.NewReader(store)
			if err != nil {
				return err
			}
			written, err := svc.CompactHistory(context.Background(), tileSize)
			if err != nil {
				return err
			}
			return rt.writeJSON(struct {
				TileSize uint64 `json:"tile_size"`
				Written  int    `json:"written"`
			}{TileSize: tileSize, Written: written})
		},
	}
	addProofStoreFlags(cmd, &metastoreKind, &metastorePath, &proofDir)
	cmd.Flags().Uint64Var(&tileSize, "tile-size", 0, "history tile size (default from config)")
	return cmd
}
