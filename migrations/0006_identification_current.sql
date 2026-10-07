-- Passive identification (phase 6). Which identification of a host, field
-- and source is current: a probe's latest value, a passive identifier's
-- adopted one (docs/DATA_MODEL.md §5.7), so a restart resumes exactly
-- where the correlator was. Before this migration the OUI, proxy-ARP
-- detection and the probes wrote identifications, and the latest of each
-- host, field and source was current.
ALTER TABLE identifications ADD COLUMN current INTEGER NOT NULL DEFAULT 0 CHECK (current IN (0, 1));
UPDATE identifications SET current = 1 WHERE id IN (
    SELECT id FROM (
        SELECT id, row_number() OVER (PARTITION BY host_id, field, source ORDER BY last_seen DESC, id DESC) AS n
        FROM identifications
    ) WHERE n = 1
);
