-- The kernel clock's synchronisation state when each event was written
-- (NFR-REL-2): synced, unsynced or unknown. Events written before this
-- migration assumed a synchronised clock without checking it, so they are
-- unknown. See docs/DATA_MODEL.md §7.
ALTER TABLE events ADD COLUMN clock_sync TEXT NOT NULL DEFAULT 'unknown'
    CHECK (clock_sync IN ('synced', 'unsynced', 'unknown'));
ALTER TABLE events DROP COLUMN clock_synced;
