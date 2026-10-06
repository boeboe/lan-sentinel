package store

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	"lan-sentinel/internal/clock"
)

// CompactBatch is how many rows one compaction step touches. Each step is
// one op in the writer's queue, so compaction never holds the writer long.
const CompactBatch = 2000

// Retention configures compaction (storage.retention, docs/DATA_MODEL.md
// §9). Zero durations keep rows forever; a zero MaxDBSize disables the cap.
type Retention struct {
	Observations time.Duration // raw observations
	Rollups      time.Duration // hourly roll-ups
	Events       time.Duration
	MaxDBSize    int64 // bytes in use (pages minus free pages)
}

// CompactResult reports one compaction run.
type CompactResult struct {
	RolledUp      int64 // raw observations folded into roll-ups and deleted
	RollupsPruned int64
	EventsPruned  int64
	SizeBefore    int64
	SizeAfter     int64
}

// Compact runs one retention pass as of now. Raw observations older than
// their retention are folded into hourly roll-ups (one row per context,
// host, source, MAC, IP and hour, unbound ones included) and deleted;
// roll-ups and events older than theirs are deleted. Then, while the data
// is larger than MaxDBSize, the oldest raw observations are rolled up, then
// the oldest roll-ups and finally the oldest events are deleted. Current
// state and binding tables are never pruned. Freed pages are returned to
// the file system (auto_vacuum=INCREMENTAL).
func (s *Store) Compact(ctx context.Context, r Retention, now time.Time) (CompactResult, error) {
	var res CompactResult
	var err error
	if res.SizeBefore, err = s.UsedSize(ctx); err != nil {
		return res, err
	}
	steps := []struct {
		keep  time.Duration
		count *int64
		run   func(ctx context.Context, tx *sql.Tx, before int64) (int64, error)
	}{
		{r.Observations, &res.RolledUp, rollUp},
		{r.Rollups, &res.RollupsPruned, pruneRollups},
		{r.Events, &res.EventsPruned, pruneEvents},
	}
	for _, st := range steps {
		if st.keep <= 0 {
			continue
		}
		before := now.Add(-st.keep).UnixMilli()
		if err := s.batches(ctx, st.count, func(ctx context.Context, tx *sql.Tx) (int64, error) {
			return st.run(ctx, tx, before)
		}); err != nil {
			return res, err
		}
	}
	if r.MaxDBSize > 0 {
		for _, st := range steps {
			for {
				size, err := s.UsedSize(ctx)
				if err != nil {
					return res, err
				}
				if size <= r.MaxDBSize {
					break
				}
				var n int64
				if err := s.step(ctx, &n, func(ctx context.Context, tx *sql.Tx) (int64, error) {
					return st.run(ctx, tx, now.UnixMilli()+1)
				}); err != nil {
					return res, err
				}
				*st.count += n
				if n == 0 {
					break // this table is empty; prune the next
				}
			}
		}
	}
	if res.RolledUp+res.RollupsPruned+res.EventsPruned > 0 {
		if err := s.step(ctx, new(int64), func(ctx context.Context, tx *sql.Tx) (int64, error) {
			_, err := tx.ExecContext(ctx, `PRAGMA incremental_vacuum`)
			return 0, err
		}); err != nil {
			return res, err
		}
	}
	res.SizeAfter, err = s.UsedSize(ctx)
	return res, err
}

// batches repeats fn, one committed op at a time, until it handles fewer
// than CompactBatch rows, adding the counts to total.
func (s *Store) batches(ctx context.Context, total *int64, fn func(context.Context, *sql.Tx) (int64, error)) error {
	for {
		var n int64
		if err := s.step(ctx, &n, fn); err != nil {
			return err
		}
		*total += n
		if n < CompactBatch {
			return nil
		}
	}
}

// step queues fn as one op, waits for it to be committed and stores its
// row count in n.
func (s *Store) step(ctx context.Context, n *int64, fn func(context.Context, *sql.Tx) (int64, error)) error {
	var opErr error
	if err := s.Submit(ctx, func(ctx context.Context, tx *sql.Tx) error {
		*n, opErr = fn(ctx, tx)
		return opErr
	}); err != nil {
		return err
	}
	if err := s.Flush(ctx); err != nil {
		return err
	}
	if opErr != nil {
		return fmt.Errorf("compact: %w", opErr)
	}
	return nil
}

// rollUp folds the oldest batch of observations older than before into
// observation_rollups and deletes them. Both statements select the same
// batch: they run in one transaction on the only writer.
func rollUp(ctx context.Context, tx *sql.Tx, before int64) (int64, error) {
	const batch = `SELECT id FROM observations WHERE ts < ? ORDER BY ts, id LIMIT ?`
	if _, err := tx.ExecContext(ctx, `INSERT INTO observation_rollups (hour, context_id, host_id, source, mac, ip, count, first_ts, last_ts)
		SELECT ts / 3600000 * 3600000, context_id, host_id, source, mac, ip, count(*), min(ts), max(ts)
		FROM observations WHERE id IN (`+batch+`)
		GROUP BY 1, context_id, host_id, source, mac, ip
		ON CONFLICT (hour, context_id, coalesce(host_id, ''), source, coalesce(mac, ''), coalesce(ip, '')) DO UPDATE SET
			count = count + excluded.count, first_ts = min(first_ts, excluded.first_ts), last_ts = max(last_ts, excluded.last_ts)`,
		before, CompactBatch); err != nil {
		return 0, err
	}
	return deleteOldest(ctx, tx, `DELETE FROM observations WHERE id IN (`+batch+`)`, before)
}

func pruneRollups(ctx context.Context, tx *sql.Tx, before int64) (int64, error) {
	return deleteOldest(ctx, tx, `DELETE FROM observation_rollups WHERE id IN (
		SELECT id FROM observation_rollups WHERE hour < ? ORDER BY hour, id LIMIT ?)`, before)
}

func pruneEvents(ctx context.Context, tx *sql.Tx, before int64) (int64, error) {
	return deleteOldest(ctx, tx, `DELETE FROM events WHERE id IN (SELECT id FROM events WHERE ts < ? ORDER BY ts, id LIMIT ?)`, before)
}

func deleteOldest(ctx context.Context, tx *sql.Tx, query string, before int64) (int64, error) {
	res, err := tx.ExecContext(ctx, query, before, CompactBatch)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// UsedSize is the size of the data in bytes: the database's pages minus
// its free pages (lan_sentinel_db_size_bytes).
func (s *Store) UsedSize(ctx context.Context) (int64, error) {
	var size int64
	err := s.View(ctx, func(ctx context.Context, tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT (page_count - freelist_count) * page_size
			FROM pragma_page_count(), pragma_freelist_count(), pragma_page_size()`).Scan(&size)
	})
	if err != nil {
		return 0, fmt.Errorf("database size: %w", err)
	}
	return size, nil
}

// RunCompaction compacts at start and then every interval until ctx is
// cancelled. retention is read before every run, so it follows reloads.
func (s *Store) RunCompaction(ctx context.Context, clk clock.Clock, interval time.Duration, retention func() Retention, log *slog.Logger) {
	t := clk.NewTicker(interval)
	defer t.Stop()
	for {
		start := time.Now()
		res, err := s.Compact(ctx, retention(), clk.Now())
		switch {
		case ctx.Err() != nil:
			return
		case err != nil:
			log.Error("compaction failed", "err", err)
		case res.RolledUp+res.RollupsPruned+res.EventsPruned > 0:
			log.Info("compaction", "rolled_up", res.RolledUp, "rollups_pruned", res.RollupsPruned,
				"events_pruned", res.EventsPruned, "size_before", res.SizeBefore, "size_after", res.SizeAfter,
				"duration", time.Since(start).Round(time.Millisecond))
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C():
		}
	}
}
