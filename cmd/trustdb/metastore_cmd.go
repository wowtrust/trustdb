package main

import (
	"context"

	"github.com/wowtrust/trustdb/internal/anchorschedule"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/proofstore"
	"github.com/wowtrust/trustdb/internal/trusterr"
	"github.com/spf13/cobra"
)

const metastoreScanPageSize = 1024

func newMetastoreCommand(rt *runtimeConfig) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "metastore",
		Short: "Manage the trustdb proof/meta store",
	}
	cmd.AddCommand(newMetastoreMigrateCommand(rt))
	return cmd
}

// migrateReport is the JSON document emitted by `trustdb metastore migrate`
// so operators and wrapper scripts can sanity-check a migration run in
// CI. Skipped counts entries retained at the destination when overwrite is
// disabled.
type migrateReport struct {
	From            string `json:"from"`
	To              string `json:"to"`
	Manifests       int    `json:"manifests"`
	Bundles         int    `json:"bundles"`
	Roots           int    `json:"roots"`
	GlobalLeaves    int    `json:"global_leaves"`
	GlobalNodes     int    `json:"global_nodes"`
	GlobalState     bool   `json:"global_state"`
	STHs            int    `json:"sths"`
	GlobalTiles     int    `json:"global_tiles"`
	AnchorResults   int    `json:"anchor_results"`
	AnchorSchedules int    `json:"anchor_schedules"`
	Skipped         int    `json:"skipped"`
}

type sthAnchorScheduleLister interface {
	ListSTHAnchorSchedules(context.Context) ([]model.STHAnchorSchedule, error)
}

func newMetastoreMigrateCommand(rt *runtimeConfig) *cobra.Command {
	var fromPath, toPath, toKindStr string
	var overwrite bool
	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Copy portable proof, global-log, and anchor data from a file-backed proofstore into another store",
		RunE: func(cmd *cobra.Command, args []string) error {
			if fromPath == "" {
				return usageError("metastore migrate requires --from")
			}
			if toPath == "" {
				return usageError("metastore migrate requires --to")
			}
			toKind := proofstore.Backend(toKindStr)
			if toKind == "" {
				toKind = proofstore.BackendPebble
			}
			ctx := context.Background()

			src, err := proofstore.Open(proofstore.Config{Kind: proofstore.BackendFile, Path: fromPath})
			if err != nil {
				return trusterr.Wrap(trusterr.CodeInternal, "open source proofstore", err)
			}
			defer func() { _ = src.Close() }()

			dst, err := proofstore.Open(proofstore.Config{Kind: toKind, Path: toPath})
			if err != nil {
				return trusterr.Wrap(trusterr.CodeInternal, "open destination proofstore", err)
			}
			defer func() { _ = dst.Close() }()

			resultLister, ok := src.(proofstore.STHAnchorResultLister)
			if !ok {
				return trusterr.New(trusterr.CodeFailedPrecondition, "source proofstore cannot enumerate STH anchor results")
			}
			resultWriter, ok := dst.(proofstore.STHAnchorResultWriter)
			if !ok {
				return trusterr.New(trusterr.CodeFailedPrecondition, "destination proofstore cannot write STH anchor results")
			}
			scheduleLister, ok := src.(sthAnchorScheduleLister)
			if !ok {
				return trusterr.New(trusterr.CodeFailedPrecondition, "source proofstore cannot enumerate STH anchor schedules")
			}
			scheduleRestorer, ok := dst.(proofstore.STHAnchorScheduleRestorer)
			if !ok {
				return trusterr.New(trusterr.CodeFailedPrecondition, "destination proofstore cannot restore STH anchor schedules")
			}
			var scheduleReplacer proofstore.STHAnchorScheduleReplacer
			if overwrite {
				scheduleReplacer, ok = dst.(proofstore.STHAnchorScheduleReplacer)
				if !ok {
					return trusterr.New(trusterr.CodeFailedPrecondition, "destination proofstore cannot overwrite STH anchor schedules")
				}
			}

			report := migrateReport{From: fromPath, To: toPath}

			afterBatchID := ""
			for {
				manifests, err := src.ListManifestsAfter(ctx, afterBatchID, metastoreScanPageSize)
				if err != nil {
					return err
				}
				if len(manifests) == 0 {
					break
				}
				for _, manifest := range manifests {
					manifestExists := false
					if !overwrite {
						if existing, err := dst.GetManifest(ctx, manifest.BatchID); err == nil && existing.BatchID != "" {
							manifestExists = true
							report.Skipped++
						}
					}

					for _, recordID := range manifest.RecordIDs {
						if !overwrite {
							if existing, err := dst.GetBundle(ctx, recordID); err == nil && existing.RecordID != "" {
								report.Skipped++
								continue
							}
						}
						bundle, err := src.GetBundle(ctx, recordID)
						if err != nil {
							if code := trusterr.CodeOf(err); code == trusterr.CodeNotFound {
								// A prepared manifest can legitimately
								// reference records whose bundles were not
								// yet written; skip them and let the batch
								// pipeline re-materialise the bundle later.
								report.Skipped++
								continue
							}
							return err
						}
						if err := dst.PutBundle(ctx, bundle); err != nil {
							return err
						}
						report.Bundles++
					}
					// Publish the manifest after its available bundles so an
					// interrupted migration can reopen and resume safely.
					if !manifestExists {
						if err := dst.PutManifest(ctx, manifest); err != nil {
							return err
						}
						report.Manifests++
					}
				}
				afterBatchID = manifests[len(manifests)-1].BatchID
			}

			afterRootClosedAt := int64(0)
			for {
				roots, err := src.ListRootsAfter(ctx, afterRootClosedAt, metastoreScanPageSize)
				if err != nil {
					return err
				}
				if len(roots) == 0 {
					break
				}
				for _, root := range roots {
					if err := dst.PutRoot(ctx, root); err != nil {
						return err
					}
					report.Roots++
				}
				afterRootClosedAt = roots[len(roots)-1].ClosedAtUnixN
			}

			nextLeafIndex := uint64(0)
			for {
				leaves, err := src.ListGlobalLeavesRange(ctx, nextLeafIndex, metastoreScanPageSize)
				if err != nil {
					return err
				}
				if len(leaves) == 0 {
					break
				}
				for _, leaf := range leaves {
					if !overwrite {
						if _, ok, err := dst.GetGlobalLeaf(ctx, leaf.LeafIndex); err != nil {
							return err
						} else if ok {
							report.Skipped++
							nextLeafIndex = leaf.LeafIndex + 1
							continue
						}
					}
					if err := dst.PutGlobalLeaf(ctx, leaf); err != nil {
						return err
					}
					report.GlobalLeaves++
					nextLeafIndex = leaf.LeafIndex + 1
				}
			}

			afterNodeLevel, afterNodeStart := ^uint64(0), ^uint64(0)
			for {
				nodes, err := src.ListGlobalLogNodesAfter(ctx, afterNodeLevel, afterNodeStart, metastoreScanPageSize)
				if err != nil {
					return err
				}
				if len(nodes) == 0 {
					break
				}
				for _, node := range nodes {
					if !overwrite {
						if _, ok, err := dst.GetGlobalLogNode(ctx, node.Level, node.StartIndex); err != nil {
							return err
						} else if ok {
							report.Skipped++
							afterNodeLevel, afterNodeStart = node.Level, node.StartIndex
							continue
						}
					}
					if err := dst.PutGlobalLogNode(ctx, node); err != nil {
						return err
					}
					report.GlobalNodes++
					afterNodeLevel, afterNodeStart = node.Level, node.StartIndex
				}
			}

			state, stateOK, err := src.GetGlobalLogState(ctx)
			if err != nil {
				return err
			}
			if stateOK {
				if !overwrite {
					if _, ok, err := dst.GetGlobalLogState(ctx); err != nil {
						return err
					} else if ok {
						report.Skipped++
					} else {
						if err := dst.PutGlobalLogState(ctx, state); err != nil {
							return err
						}
						report.GlobalState = true
					}
				} else {
					if err := dst.PutGlobalLogState(ctx, state); err != nil {
						return err
					}
					report.GlobalState = true
				}
			}

			afterSTHTreeSize := uint64(0)
			for {
				sths, err := src.ListSignedTreeHeadsAfter(ctx, afterSTHTreeSize, metastoreScanPageSize)
				if err != nil {
					return err
				}
				if len(sths) == 0 {
					break
				}
				for _, sth := range sths {
					if !overwrite {
						if _, ok, err := dst.GetSignedTreeHead(ctx, sth.TreeSize); err != nil {
							return err
						} else if ok {
							report.Skipped++
							afterSTHTreeSize = sth.TreeSize
							continue
						}
					}
					if err := dst.PutSignedTreeHead(ctx, sth); err != nil {
						return err
					}
					report.STHs++
					afterSTHTreeSize = sth.TreeSize
				}
			}

			afterTileLevel, afterTileStart := ^uint64(0), ^uint64(0)
			for {
				tiles, err := src.ListGlobalLogTilesAfter(ctx, afterTileLevel, afterTileStart, metastoreScanPageSize)
				if err != nil {
					return err
				}
				if len(tiles) == 0 {
					break
				}
				for _, tile := range tiles {
					if err := dst.PutGlobalLogTile(ctx, tile); err != nil {
						return err
					}
					report.GlobalTiles++
					afterTileLevel, afterTileStart = tile.Level, tile.StartIndex
				}
			}

			// Snapshot mutable scheduler state before copying immutable results.
			// Restore clears only process-local lease ownership.
			schedules, err := scheduleLister.ListSTHAnchorSchedules(ctx)
			if err != nil {
				return err
			}
			anchorschedule.Sort(schedules)

			resultReader, _ := dst.(proofstore.STHAnchorResultKeyedReader)
			afterAnchorResult := model.STHAnchorResultKey{}
			for {
				results, err := resultLister.ListSTHAnchorResultsAfter(ctx, afterAnchorResult, metastoreScanPageSize)
				if err != nil {
					return err
				}
				if len(results) == 0 {
					break
				}
				for _, result := range results {
					resultKey := anchorschedule.ResultKey(result)
					if anchorschedule.CompareResultKeys(resultKey, afterAnchorResult) <= 0 {
						return trusterr.New(trusterr.CodeDataLoss, "STH anchor result listing did not advance")
					}
					if !overwrite && resultReader != nil {
						if _, found, err := resultReader.GetSTHAnchorResultForKey(ctx, resultKey); err != nil {
							return err
						} else if found {
							report.Skipped++
							afterAnchorResult = resultKey
							continue
						}
					}
					if err := resultWriter.PutSTHAnchorResult(ctx, result); err != nil {
						return err
					}
					report.AnchorResults++
					afterAnchorResult = resultKey
				}
			}

			scheduleReader, _ := dst.(proofstore.STHAnchorScheduleStore)
			for _, schedule := range schedules {
				schedule, err = anchorschedule.ClearLeaseForRestore(schedule)
				if err != nil {
					return trusterr.Wrap(trusterr.CodeDataLoss, "migrate invalid STH anchor schedule", err)
				}
				if !overwrite && scheduleReader != nil {
					if _, found, err := scheduleReader.GetSTHAnchorSchedule(ctx, schedule.Key); err != nil {
						return err
					} else if found {
						report.Skipped++
						continue
					}
				}
				if overwrite {
					err = scheduleReplacer.ReplaceSTHAnchorSchedule(ctx, schedule)
				} else {
					err = scheduleRestorer.PutSTHAnchorSchedule(ctx, schedule)
				}
				if err != nil {
					return err
				}
				report.AnchorSchedules++
			}

			if manager, ok := dst.(proofstore.IdempotencyProjectionManager); ok {
				if err := manager.EnsureIdempotencyProjection(ctx); err != nil {
					return trusterr.Wrap(trusterr.CodeDataLoss, "rebuild migrated idempotency projection", err)
				}
			}
			return rt.writeJSON(report)
		},
	}
	cmd.Flags().StringVar(&fromPath, "from", "", "source file-backed proof store directory")
	cmd.Flags().StringVar(&toPath, "to", "", "destination proof store directory")
	cmd.Flags().StringVar(&toKindStr, "to-kind", "pebble", "destination backend kind: file or pebble (default pebble)")
	cmd.Flags().BoolVar(&overwrite, "overwrite", false, "overwrite existing entries instead of skipping")
	return cmd
}
