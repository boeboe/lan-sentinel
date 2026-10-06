-- Active discovery (phase 4). What a protocol-specific UDP probe learnt
-- about a service (NTP version and stratum, ...), as a JSON object of
-- strings. See docs/DATA_MODEL.md §5.5.
ALTER TABLE services ADD COLUMN detail_json TEXT NOT NULL DEFAULT '{}';

-- The latest operator scan per interface (`daemon status`).
CREATE INDEX scans_started ON scans (started_at);
